// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// DISTRIBUTION A. Approved for public release; distribution unlimited.
// OPSEC #4584.

mod lifecycle_builder;
mod lifecycle_graph;
mod state_machine;
mod state;

use std::{os::raw::c_char, ffi::CStr, sync::{Arc, Mutex, Weak}, fmt, error::Error};
use crate::{rcl_bindings::*, ClientBase, GuardCondition, ServiceBase, SubscriptionBase, ParameterOverrideMap, Context, RclrsError, Client, QoSProfile, Publisher,  Subscription, SubscriptionCallback, vendor::lifecycle_msgs::{self, srv::{ChangeState_Request, ChangeState_Response}}, ToResult};
use self::{lifecycle_builder::LifecycleNodeBuilder, state::State};

use rosidl_runtime_rs::{Message, RmwMessage, Service};
use lifecycle_msgs::srv::ChangeState;
use lifecycle_msgs::msg::Transition;

// pub enum LifecycleCallbackReturn {
//     // The transition callback successfully performed its required functionality.
//     Success,
//     // The transition callback failed to perform its required functionality.
//     Failure,
//     // The transition callback encountered an error that requires special cleanup, if possible.
//     Error,
// }

// impl TryFrom<lifecycle_msgs__msg__Transition> for LifecycleCallbackReturn {
//     type Error = &'static str;
//     fn try_from(value: lifecycle_msgs__msg__Transition) -> Result<Self, <Self as TryFrom<lifecycle_msgs__msg__Transition>>::Error> {
//         match value.id {
//             97 => Ok(Self::Success),
//             98 => Ok(Self::Failure),
//             99 => Ok(Self::Error),
//             _ => Err("Invalid callback return ID: \"{}\"!")
//         }
//     }
// }

// impl LifecycleCallbackReturn {
//     pub fn id(&self) -> u8 {
//         match self {
//             Self::Success => 97,
//             Self::Failure => 98,
//             Self::Error => 99
//         }
//     }

//     pub fn label(&self) -> String {
//         match self {
//             Self::Success => "TRANSITION_CALLBACK_SUCCESS",
//             Self::Failure => "TRANSITION_CALLBACK_FAILURE",
//             Self::Error => "TRANSITION_CALLBACK_ERROR",
//         }.into()
//     }
// }

type LifecycleCallback = Box<dyn Fn(&State) -> Transition + Send + 'static>;

pub struct LifecycleNode {
    pub(crate) rcl_node_mtx: Arc<Mutex<rcl_node_t>>,
    pub(crate) rcl_context_mtx: Arc<Mutex<rcl_context_t>>,
    pub(crate) clients: Vec<Weak<dyn ClientBase>>,
    pub(crate) guard_conditions: Vec<Weak<GuardCondition>>,
    pub(crate) services: Vec<Weak<dyn ServiceBase>>,
    pub(crate) subscriptions: Vec<Weak<dyn SubscriptionBase>>,
    pub(crate) on_activate: Mutex<LifecycleCallback>,
    pub(crate) on_cleanup: Mutex<LifecycleCallback>,
    pub(crate) on_configure: Mutex<LifecycleCallback>,
    pub(crate) on_deactivate: Mutex<LifecycleCallback>,
    pub(crate) on_error: Mutex<LifecycleCallback>,
    pub(crate) on_shutdown: Mutex<LifecycleCallback>,
    state_machine: Arc<Mutex<rcl_lifecycle_state_machine_t>>,
    _parameter_map: ParameterOverrideMap,
}

impl Eq for LifecycleNode {}

impl PartialEq for LifecycleNode {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.rcl_node_mtx, &other.rcl_node_mtx)
    }
}

impl fmt::Debug for LifecycleNode {
    fn fmt (&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Node")
        .field("fully_qualified_name", &self.fully_qualified_name())
        .finish()
    }
}

impl LifecycleNode {
    /// Creates a new lifecycle node in the empty namespace.
    /// 
    /// See [`LifecycleNodeBuilder::new()`] for documentation.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(context: &Context, node_name: &str) -> Result<LifecycleNode, Box<dyn Error>> {
        Self::builder(context, node_name).build()
    }


    /// Returns the name of the lifecycle node.
    /// 
    /// This returns the name after remapping, so it is not necessarily the same as the name that
    /// was used when creating the lifecycle node.
    pub fn name(&self) -> String {
        self.call_string_getter(rcl_node_get_name)
    }

    /// Returns the namespace of the lifecycle node.
    /// 
    /// This returns the namespace after remapping, so it is not necessarily the same as the
    /// namespace that was used when creating the lifecycle node.
    pub fn namepsace(&self) -> String {
        self.call_string_getter(rcl_node_get_namespace)
    }

    /// Returns the fully qualified name of the lifecycle node.
    /// 
    /// The fully qualified name of the node is the lifecycle node namespace combined with the node name.
    /// It is subject to the remappings shown in [`LifecycleNode::name()`] and [`LifecycleNode::namespace()`]
    pub fn fully_qualified_name(&self) -> String {
        self.call_string_getter(rcl_node_get_fully_qualified_name)
    }

    /// Helper for name(), namespace(), fully_qualified_name()
    fn call_string_getter(
        &self,
        getter: unsafe extern "C" fn(*const rcl_node_t) -> *const c_char,
    ) -> String {
        unsafe { call_string_getter_with_handle(&self.rcl_node_mtx.lock().unwrap(), getter) }
    }

    /// Creates a [`Client`][1]
    /// 
    /// [1]: crate::Client
    pub fn create_client<T>(&mut self, topic: &str) -> Result<Arc<Client<T>>, RclrsError>
    where
        T: rosidl_runtime_rs::Service,
    {
        let client = Arc::new(Client::<T>::new(Arc::clone(&self.rcl_node_mtx), topic)?);
        self.clients
            .push(Arc::downgrade(&client) as Weak<dyn ClientBase>);
        Ok(client)
    }

    /// Creates a [`GuardCondition`][1] with no callback.
    /// 
    /// A weak pointer to the `GuardCondition`is stored within this lifecycle node.
    /// When this lifecycle node is added to a wait set (e.g. when calling `spin_once`[2]
    /// with this lifecycle node as an argument), the guard condition can be used to
    /// interrupt the wait.
    /// 
    /// [1]: crate::GuardCondition
    /// [2]: crate::spin_once
    pub fn create_guard_condition(&mut self) -> Arc<GuardCondition> {
        let guard_condition = Arc::new(GuardCondition::new_with_rcl_context(
            &mut self.rcl_context_mtx.lock().unwrap(),
            None,
        ));
        self.guard_conditions
            .push(Arc::downgrade(&guard_condition) as Weak<GuardCondition>);
        guard_condition
    }

    /// Creates a [`GuardCondition`][1] with a callback.
    /// 
    /// A weak pointer to the `GuardCondition` is stored within this lifecycle node.
    /// When this lifecycle node is added to a wait set (e.g. when calling `spin_once` [2]
    /// with this lifecycle node as an argument), the guard condition can be used to
    /// interrupt the wait.
    /// 
    /// [1]: crate::GuardCondition
    /// [2]: crate::spin_once
    pub fn create_guard_condition_with_callback<F>(&mut self, callback: F) -> Arc<GuardCondition>
    where
        F: Fn() + Send + Sync + 'static,
    {
        let guard_condition = Arc::new(GuardCondition::new_with_rcl_context(
            &mut self.rcl_context_mtx.lock().unwrap(),
            Some(Box::new(callback) as Box<dyn Fn() + Send + Sync>),
        ));
        self.guard_conditions
            .push(Arc::downgrade(&guard_condition) as Weak<GuardCondition>);
        guard_condition
    }

    /// Creates a [`Publisher`][1].
    /// 
    /// [1]: crate::Publisher
    pub fn create_publisher<T>(
        &self,
        topic: &str,
        qos: QoSProfile,
    ) -> Result<Publisher<T>, RclrsError>
    where
        T: Message,
    {
        Publisher::<T>::new(Arc::clone(&self.rcl_node_mtx), topic, qos)
    }

    /// Creates a [`Service`][1].
    /// 
    /// [1]: crate::Service
    pub fn create_service<T, F>(
        &mut self,
        topic: &str,
        callback: F,
    ) -> Result<Arc<crate::Service<T>>, RclrsError>
    where
        T: rosidl_runtime_rs::Service,
        F: Fn(&rmw_request_id_t, T::Request) -> T::Response + 'static + Send,
    {
        let service = Arc::new(crate::Service::<T>::new(
            Arc::clone(&self.rcl_node_mtx),
            topic,
            callback,
        )?);
        self.services
            .push(Arc::downgrade(&service) as Weak<dyn ServiceBase>);
        Ok(service)
    }

    /// Creates a [`Subscription`][1]
    /// 
    /// [1]: crate::Subscription
    pub fn create_subscription<T, Args>(
        &mut self,
        topic: &str,
        qos: QoSProfile,
        callback: impl SubscriptionCallback<T, Args>,
    ) -> Result<Arc<Subscription<T>>, RclrsError>
    where
        T: Message,
    {
        let subscription = Arc::new(Subscription::<T>::new(
                Arc::clone(&self.rcl_node_mtx),
                topic,
                qos,
                callback,
        )?);
        self.subscriptions
            .push(Arc::downgrade(&subscription) as Weak<dyn SubscriptionBase>);
        Ok(subscription)
    }

    /// Returns the subscriptions that have not been dropped yet.
    pub(crate) fn live_subscriptions(&self) -> Vec<Arc<dyn SubscriptionBase>> {
        self.subscriptions
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    /// Returns the clients that have not been dropped yet.
    pub(crate) fn live_clients(&self) -> Vec<Arc<dyn ClientBase>> {
        self.clients.iter().filter_map(Weak::upgrade).collect()
    }

    /// Returns the guard conditions that have not been dropped yet.
    pub(crate) fn live_guard_conditions(&self) -> Vec<Arc<GuardCondition>> {
        self.guard_conditions
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    /// Returns the services that have not been dropped yet.
    pub(crate) fn live_services(&self) -> Vec<Arc<dyn ServiceBase>> {
        self.services.iter().filter_map(Weak::upgrade).collect()
    }

    /// Returns the ROS domain ID that the lifecycle node is using.
    /// 
    /// The domain ID controls which nodes can send messages to each other, see the [ROS 2 concept article][1].
    /// it can be set through the `ROS_DOMAIN_ID` environment variable.
    /// 
    /// [1]: https://docs.ros.org/en/rolling/Concepts/About-Domain-ID.html
    pub fn domain_id(&self) -> usize {
        let rcl_node = &*self.rcl_node_mtx.lock().unwrap();
        let mut domain_id: usize = 0;
        let ret = unsafe {
            // Safety: no preconditions for this function.
            rcl_node_get_domain_id(rcl_node, &mut domain_id)
        };

        debug_assert_eq!(ret, 0);
        domain_id
    }

    fn on_change_state(
        &self,
        header: &rmw_request_id_t,
        req: &ChangeState_Request,
        resp: Arc<ChangeState_Response>
    ) -> Result<(), RclrsError> {
        // rcl_lifecycle_state_machine_is_initialized(self.)
        Ok(())
    }

    /// Creates a [`LifecycleNodeBuilder`][1] with the given name.
    /// 
    /// Convenience function equivalent to [`LifecycleNodeBuilder::new()`][2].
    /// 
    /// [1]: crate::LifecycleNodeBuilder
    /// [2]: crate::LifecycleNodeBuilder::new
    /// 
    /// # Example
    /// ```
    /// # use rclrs::{Context, LifecycleNode, RclrsError};
    /// let context = Context::new([])?;
    /// let node = LifecycleNode::builder(&context, "my_node").build()?;
    /// assert_eq!(node.name(), "my_node");
    /// # Ok::<(), RclrsError>(())
    pub fn builder(context: &Context, node_name: &str) -> LifecycleNodeBuilder {
        LifecycleNodeBuilder::new(context, node_name)
    }
}

// Helper used to implement call_string_getter(), but also used to get the FQN in the LifecycleNode::new()
// function, which is why it's not merged into LifecycleNode::call_string_getter().
// This function is unsafe since it's possible to pass in an rcl_node_t with dangling
// pointers, etc.
unsafe fn call_string_getter_with_handle(
    rcl_node: &rcl_node_t,
    getter: unsafe extern "C" fn(*const rcl_node_t) -> *const c_char,
) -> String {
    let char_ptr = getter(rcl_node);
    debug_assert!(!char_ptr.is_null());
    // SAFETY: The returned CStr is immediately converted to an owned string,
    // so the lifetime is no issue. the ptr is valid as per the documentation
    // of rcl_node_get_name.
    let cstr = CStr::from_ptr(char_ptr);
    cstr.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn lifecycle_node_is_send_and_sync() {
        assert_send::<LifecycleNode>();
        assert_sync::<LifecycleNode>();
    }

}
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
mod state;
mod state_machine;
mod transition;

use self::{lifecycle_builder::LifecycleNodeBuilder, state::State};
use crate::{
    rcl_bindings::*,
    vendor::lifecycle_msgs::{
        self,
        srv::{
            ChangeState_Request, ChangeState_Response, GetAvailableStates_Request,
            GetAvailableStates_Response, GetAvailableTransitions_Request,
            GetAvailableTransitions_Response, GetState_Request, GetState_Response,
        },
    },
    Client, ClientBase, Context, GuardCondition, ParameterOverrideMap, Publisher, QoSProfile,
    RclrsError, ServiceBase, Subscription, SubscriptionBase, SubscriptionCallback, ToResult,
};
use std::{
    error::Error,
    ffi::{CStr, CString},
    fmt,
    os::raw::c_char,
    sync::{Arc, Mutex, Weak},
};

use lifecycle_msgs::msg::Transition;
use rosidl_runtime_rs::Message;

// The functions accessing this type, including drop(), shouldn't care about the thread
// they are running in. Therefore, this type can be safely sent to another thread.
unsafe impl Send for rcl_lifecycle_state_machine_t {}

type LifecycleCallback = Box<dyn Fn(&State) -> u8 + Send + 'static>;

/// A ROS 2 Lifecycle (managed) Node.
///
/// Lifecycle nodes are used when more fine-tuned control over a node is needed. Each node can be
/// in one of the following primary states at any given point:
/// - `Unconfigured`: The state the node is in immediately after being instantiated. Also one of two
///     states the node can be returned to after an error has occurred. In this state, there is
///     expected to be no stored state.
/// - `Inactive`: The node is not doing any processing. The node will not recieve any execution time
///     to read topics, perform processing of data, respond to functional service requests, etc.
///     Data retention on managed topics will be subject to the configured QoS policy for the
///     topic. Also, any managed service requests to a node in this state will not be answered
///     (to the caller, they will fail immediately).
/// - `Active`: The main state of the node's life cycle. The node will perform any processing,
///     respond to service requests, reads and processes data, produces output, etc.
/// - `Finalized`: The state a node ends up in immediately before being destroyed. This state
///     is always terminal - the only valid transition is to be destroyed. This state exists to
///     support debugging and introspection, and is one of two states the node can be returned
///     to after an error has occurred.
///
/// Additionally, there are also 6 "transition" states that the node can be in, when it is moving
/// between primary states:
/// - `Configuring` (Unconfigured -> Inactive): The node's `on_configure` callback will be called to
///     allow the node to load its configuration and conduct any required setup. The configuration
///     of a node will typically involve tasks that must be performed once during a node's
///     lifetime, such as obtaining permanent memory buffers, and setting up topic publications
///     and subscriptions that do not change.
/// - `CleaningUp` (Inactive -> Unconfigured): The node's `on_cleanup` callback will be called to
///     clear all state and return the node to a functionally equivalent state as when it was first
///     created. If cleanup cannot be successfully achieved, it will transition to
///     `ErrorProcessing`.
/// - `ShuttingDown` (Unconfigured/Inactive/Active -> Finalized): The node's `on_shutdown` callback
///     will be called to do any cleanup necessary before destruction.
/// - `Activating` (Inactive -> Active): The node's `on_activate` callback will be called to do any
///     final preparations to start executing. This may include acquiring resources that are only
///     held while the node is actually active, such as access to hardware. Ideally, no preparation
///     that requires significant time (such as lengthy hardwar initialization) should be performed
///     in this callback.
/// - `Deactivating` (Active -> Inactive): The node's `on_deactivate` callback will be called to
///     reverse the changes made by `on_activate`, so as to return the node to a base `Inactive`
///     state.
/// - `ErrorProcessing` (Special case: This handles if an error is raised in any other primary or
///     transition state, and will either put the node into a Finalized or Unconfigured state):
///     The node's `on_error` callback will be called to attempt to clean up any error conditions
///     within the node. If the error handling is successfully completed, the node can return to
///     `Unconfigured`. If a full cleanup is not possible, it must fail and transition the node to
///     the `Finalized` state for destruction.
pub struct LifecycleNode {
    pub(crate) rcl_node_mtx: Arc<Mutex<rcl_node_t>>,
    pub(crate) rcl_context_mtx: Arc<Mutex<rcl_context_t>>,
    pub(crate) clients: Vec<Weak<dyn ClientBase>>,
    pub(crate) guard_conditions: Vec<Weak<GuardCondition>>,
    pub(crate) services: Vec<Weak<dyn ServiceBase>>,
    pub(crate) subscriptions: Vec<Weak<dyn SubscriptionBase>>,
    state_machine: Arc<state_machine::LifecycleMachine>,
    _parameter_map: ParameterOverrideMap,
}

impl Drop for LifecycleNode {
    fn drop(&mut self) {
        let mut node = self.rcl_node_mtx.lock().unwrap();
        let mut state_machine = self.state_machine.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function
        unsafe {
            rcl_lifecycle_state_machine_fini(&mut *state_machine, &mut *node)
                .ok()
                .unwrap();
        }
    }
}

impl Eq for LifecycleNode {}

impl PartialEq for LifecycleNode {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.rcl_node_mtx, &other.rcl_node_mtx)
    }
}

impl fmt::Debug for LifecycleNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
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
    use crate::{
        create_node, spin,
        vendor::lifecycle_msgs::srv::{
            ChangeState, GetAvailableStates, GetAvailableTransitions, GetState,
        },
        Context, Node,
    };

    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    // const LIFECYCLE_NODE_NAME: &str = "lc_talker";
    // const NODE_GET_STATE_TOPIC: &str = "/lc_talker/get_state";
    // const NODE_CHANGE_STATE_TOPIC: &str = "/lc_talker/change_state";
    // const NODE_GET_AVAILABLE_STATES_TOPIC: &str = "/lc_talker/get_available_states";
    // const NODE_GET_AVAILABLE_TRANSITIONS_TOPIC: &str = "/lc_talker/get_available_transitions";
    // const NODE_GET_TRANSITION_GRAPH_TOPIC: &str = "/lc_talker/get_transition_graph";

    #[test]
    fn lifecycle_node_is_send_and_sync() {
        assert_send::<LifecycleNode>();
        assert_sync::<LifecycleNode>();
    }

    // #[test]
    // fn able_to_get_available_states() -> Result<(), Box<dyn Error>> {
    //     let context = Context::new([])?;
    //     let node = create_node(&context, "lifecycle_test_client")?;
    //     let lifecycle_test_client = LifecycleServiceClient::new(node)?;
    //     // let states = tokio_test::block_on(lifecycle_test_client.get_available_states());
    //     let states_future = lifecycle_test_client.get_available_states();
    //     let rclrs_spin = tokio_test::task::spawn(move || spin(&lifecycle_test_client.node));
    //     let states = tokio_test::block_on(states_future);
    //     if states.len() != 11 {
    //         return Err("incorrect number of states returned".into());
    //     }

    //     Ok(())

    // }

    // TODO(jhassold): Create tests to see if lifecycle node responds appropriately to messages for each type of state.

    #[test]
    fn test_trigger_transition() {
        let context = Context::new(vec![]).unwrap();
        let mut test_node_builder = LifecycleNode::builder(&context, "test_node");

        // `Activating` transition callback
        let on_activate_cb = |_: &State| Transition::TRANSITION_CALLBACK_SUCCESS;
        let on_activate: LifecycleCallback = Box::new(on_activate_cb);

        // `Cleanup` transition callback
        let on_cleanup_cb = |_: &State| Transition::TRANSITION_CALLBACK_SUCCESS;
        let on_cleanup: LifecycleCallback = Box::new(on_cleanup_cb);

        // `Configuring` transition callback
        let on_configure_cb = |_: &State| Transition::TRANSITION_CALLBACK_SUCCESS;
        let on_configure: LifecycleCallback = Box::new(on_configure_cb);

        // `Deactivate` transition callback
        let on_deactivate_cb = |_: &State| Transition::TRANSITION_CALLBACK_SUCCESS;
        let on_deactivate: LifecycleCallback = Box::new(on_deactivate_cb);

        // Error handling callback
        let on_error_cb = |_: &State| Transition::TRANSITION_CALLBACK_SUCCESS;
        let on_error: LifecycleCallback = Box::new(on_error_cb);

        // `Shutdown` transition callback
        let on_shutdown_cb = |_: &State| Transition::TRANSITION_CALLBACK_SUCCESS;
        let on_shutdown: LifecycleCallback = Box::new(on_shutdown_cb);

        test_node_builder.on_activate = Some(on_activate);
        test_node_builder.on_cleanup = Some(on_cleanup);
        test_node_builder.on_configure = Some(on_configure);
        test_node_builder.on_deactivate = Some(on_deactivate);
        test_node_builder.on_error = Some(on_error);
        test_node_builder.on_shutdown = Some(on_shutdown);

        test_node_builder.enable_communication_interface = true;
    }
}

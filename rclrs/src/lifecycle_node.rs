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

type LifecycleCallback = Box<dyn Fn(&State) -> Transition + Send + 'static>;

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

    // pub(crate) fn on_change_state(
    //     &self,
    //     _header: &rmw_request_id_t,
    //     req: &ChangeState_Request,
    // ) -> ChangeState_Response {
    //     let mut resp = ChangeState_Response::default();
    //     let transition_id = {
    //         let state_machine = &*self.state_machine.lock().unwrap();
    //         // SAFETY: No preconditions for this function.
    //         unsafe {
    //             rcl_lifecycle_state_machine_is_initialized(state_machine)
    //                 .ok()
    //                 .unwrap()
    //         };
    //         let mut transition_id = req.transition.id;

    //         // If there's a label attached to the request, we check the transition attached to this label.
    //         // We can't compare the id of the looked up transition any further because ROS 2 service call
    //         // sets all integers to zero by default. That means if we call ROS 2 service call:
    //         // ... {transition: {label: shutdown}}
    //         // the id of the request is 0 (zero) whereas the id from the looked up transition can be different.
    //         // The result of this is that the label takes precedence over the ID.
    //         if !req.transition.label.is_empty() {
    //             // This should be safe to unwrap, since the label originated in C/C++
    //             let label_cstr = CString::new(req.transition.label.clone()).unwrap();
    //             // SAFETY: No preconditions for this function - however it may return null
    //             let rcl_transition = unsafe {
    //                 rcl_lifecycle_get_transition_by_label(
    //                     state_machine.current_state,
    //                     label_cstr.as_ptr(),
    //                 )
    //             };
    //             if rcl_transition.is_null() {
    //                 resp.success = false;
    //                 return resp;
    //             }
    //             transition_id = unsafe { (*rcl_transition).id as u8 };
    //         }
    //         transition_id
    //     };

    //     let ret = self.change_state(transition_id).unwrap();
    //     resp.success = ret.id == lifecycle_msgs::msg::Transition::TRANSITION_CALLBACK_SUCCESS;

    //     resp
    // }

    // pub(crate) fn on_get_state(
    //     &self,
    //     _header: rmw_request_id_t,
    //     _req: GetState_Request,
    // ) -> Result<GetState_Response, RclrsError> {
    //     let state_machine = &*self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function.
    //     unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok()? };

    //     // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //     // label pointer should not be null
    //     let label = unsafe {
    //         CStr::from_ptr((*state_machine.current_state).label)
    //             .to_owned()
    //             .to_string_lossy()
    //             .to_string()
    //     };
    //     // SAFETY: The state machine has been confirmed to be initialized by this point, so the id
    //     // pointer should not be null.
    //     let id = unsafe { (*state_machine.current_state).id };
    //     let current_state = lifecycle_msgs::msg::State { id, label };

    //     let resp = GetState_Response { current_state };

    //     Ok(resp)
    // }

    // pub(crate) fn on_get_available_states(
    //     &self,
    //     _header: rmw_request_id_t,
    //     _req: GetAvailableStates_Request,
    // ) -> Result<GetAvailableStates_Response, RclrsError> {
    //     let state_machine = &*self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function.
    //     unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok()? };

    //     let mut available_states = Vec::<lifecycle_msgs::msg::State>::new();
    //     for i in 0..state_machine.transition_map.states_size as isize {
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //         // label pointer should not be null
    //         let label = unsafe {
    //             CStr::from_ptr((*state_machine.transition_map.states.offset(i)).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string()
    //         };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //         // id pointer should not be null
    //         let id = unsafe { (*state_machine.transition_map.states.offset(i)).id };
    //         let available_state = lifecycle_msgs::msg::State { id, label };
    //         available_states.push(available_state);
    //     }

    //     let resp = GetAvailableStates_Response { available_states };

    //     Ok(resp)
    // }

    // pub(crate) fn on_get_available_transitions(
    //     &self,
    //     _header: rmw_request_id_t,
    //     _req: GetAvailableTransitions_Request,
    // ) -> Result<GetAvailableTransitions_Response, RclrsError> {
    //     let state_machine = &*self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function.
    //     unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok()? };

    //     let mut available_transitions = Vec::<lifecycle_msgs::msg::TransitionDescription>::new();
    //     // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //     // transition size should not be null
    //     let valid_transition_size =
    //         unsafe { (*state_machine.current_state).valid_transition_size as isize };
    //     for i in 0..valid_transition_size {
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //         // transition pointer should not be null
    //         let rcl_transition =
    //             unsafe { (*state_machine.current_state).valid_transitions.offset(i) };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so
    //         // the transition pointer should not be null
    //         let transition = unsafe {
    //             let transition_id = (*rcl_transition).id as u8;
    //             let transition_label = CStr::from_ptr((*rcl_transition).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string();
    //             lifecycle_msgs::msg::Transition {
    //                 id: transition_id,
    //                 label: transition_label,
    //             }
    //         };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so
    //         // the start state pointer should not be null
    //         let start_state = unsafe {
    //             let start_state_id = (*(*rcl_transition).start).id;
    //             let start_state_label = CStr::from_ptr((*(*rcl_transition).start).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string();
    //             lifecycle_msgs::msg::State {
    //                 id: start_state_id,
    //                 label: start_state_label,
    //             }
    //         };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so
    //         // the goal state pointer should not be null
    //         let goal_state = unsafe {
    //             let goal_state_id = (*(*rcl_transition).goal).id;
    //             let goal_state_label = CStr::from_ptr((*(*rcl_transition).goal).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string();
    //             lifecycle_msgs::msg::State {
    //                 id: goal_state_id,
    //                 label: goal_state_label,
    //             }
    //         };
    //         let trans_desc = lifecycle_msgs::msg::TransitionDescription {
    //             transition,
    //             start_state,
    //             goal_state,
    //         };
    //         available_transitions.push(trans_desc);
    //     }
    //     let resp = lifecycle_msgs::srv::GetAvailableTransitions_Response {
    //         available_transitions,
    //     };
    //     Ok(resp)
    // }

    // pub(crate) fn on_get_transition_graph(
    //     &self,
    //     _header: rmw_request_id_t,
    //     _req: GetAvailableTransitions_Request,
    // ) -> Result<GetAvailableTransitions_Response, RclrsError> {
    //     let state_machine = &*self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function.
    //     unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok()? };

    //     let mut available_transitions = Vec::<lifecycle_msgs::msg::TransitionDescription>::new();
    //     // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //     // transition size should not be null
    //     let valid_transition_size =
    //         state_machine.transition_map.transitions_size as isize;
    //     for i in 0..valid_transition_size {
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //         // transition pointer should not be null
    //         let rcl_transition =
    //             unsafe { (state_machine.transition_map).transitions.offset(i) };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so
    //         // the transition pointer should not be null
    //         let transition = unsafe {
    //             let transition_id = (*rcl_transition).id as u8;
    //             let transition_label = CStr::from_ptr((*rcl_transition).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string();
    //             lifecycle_msgs::msg::Transition {
    //                 id: transition_id,
    //                 label: transition_label,
    //             }
    //         };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so
    //         // the start state pointer should not be null
    //         let start_state = unsafe {
    //             let start_state_id = (*(*rcl_transition).start).id;
    //             let start_state_label = CStr::from_ptr((*(*rcl_transition).start).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string();
    //             lifecycle_msgs::msg::State {
    //                 id: start_state_id,
    //                 label: start_state_label,
    //             }
    //         };
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so
    //         // the goal state pointer should not be null
    //         let goal_state = unsafe {
    //             let goal_state_id = (*(*rcl_transition).goal).id;
    //             let goal_state_label = CStr::from_ptr((*(*rcl_transition).goal).label)
    //                 .to_owned()
    //                 .to_string_lossy()
    //                 .to_string();
    //             lifecycle_msgs::msg::State {
    //                 id: goal_state_id,
    //                 label: goal_state_label,
    //             }
    //         };
    //         let trans_desc = lifecycle_msgs::msg::TransitionDescription {
    //             transition,
    //             start_state,
    //             goal_state,
    //         };
    //         available_transitions.push(trans_desc);
    //     }
    //     let resp = lifecycle_msgs::srv::GetAvailableTransitions_Response {
    //         available_transitions,
    //     };
    //     Ok(resp)
    // }

    // pub fn get_current_state(&self) -> Result<State, RclrsError> {
    //     // Make sure that the state machine is initialized before doing anything
    //     let state_machine = self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function
    //     unsafe {
    //         rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
    //     }

    //     // let mut x = unsafe { state_machine.current_state };

    //     // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //     // pointer should not be null
    //     let current_state =
    //         unsafe { State::from_raw(state_machine.current_state as *mut rcl_lifecycle_state_s) };
    //     Ok(current_state)
    // }

    // pub fn get_available_states(&self) -> Result<Vec<State>, RclrsError> {
    //     // Make sure that the state machine is initialized before doing anything
    //     let state_machine = self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function
    //     unsafe {
    //         rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
    //     }

    //     let mut states = Vec::<State>::new();

    //     let states_size = state_machine.transition_map.states_size as isize;
    //     for i in 0..states_size {
    //         // SAFETY: The state machine has been confirmed to be initialized by this point, so the
    //         // pointer should not be null
    //         let available_state =
    //             unsafe { State::from_raw(state_machine.transition_map.states.offset(i)) };
    //         states.push(available_state);
    //     }

    //     Ok(states)
    // }

    // pub fn get_available_transitions(&self) -> Result<Vec<transition::Transition>, RclrsError> {
    //     // Make sure that the state machine is initialized before doing anything
    //     let state_machine = self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function
    //     unsafe {
    //         rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
    //     }

    //     let mut transitions = Vec::<transition::Transition>::new();

    //     // SAFETY: The state machine has been confirmed to be initialized at this point, so the
    //     // pointer should not be null
    //     let transitions_size =
    //         unsafe { (*state_machine.current_state).valid_transition_size as isize };
    //     for i in 0..transitions_size {
    //         // SAFETY: The state machine has been confirmed to be initialized at this point, so the
    //         // pointer should not be null
    //         let available_transition = unsafe {
    //             transition::Transition::from_raw(
    //                 (*state_machine.current_state).valid_transitions.offset(i),
    //             )
    //         };
    //         transitions.push(available_transition);
    //     }

    //     Ok(transitions)
    // }

    // pub fn get_transition_graph(&self) -> Result<Vec<transition::Transition>, RclrsError> {
    //     // Make sure that the state machine is initialized before doing anything
    //     let state_machine = self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function
    //     unsafe {
    //         rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
    //     }

    //     let mut transitions = Vec::<transition::Transition>::new();

    //     // SAFETY: The state machine has been confirmed to be initialized at this point, so the
    //     // pointer should not be null
    //     let transitions_size = state_machine.transition_map.transitions_size as isize;
    //     for i in 0..transitions_size {
    //         // SAFETY: The state machine has been confirmed to be initialized at this point, so the
    //         // pointer should not be null
    //         let available_transition = unsafe {
    //             transition::Transition::from_raw(state_machine.transition_map.transitions.offset(i))
    //         };
    //         transitions.push(available_transition);
    //     }

    //     Ok(transitions)
    // }

    // pub fn change_state(&self, transition_id: u8) -> Result<Transition, RclrsError> {
    //     // Make sure that the state machine is initialized before doing anything
    //     let mut state_machine = self.state_machine.lock().unwrap();
    //     // SAFETY: No preconditions for this function
    //     unsafe {
    //         rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
    //     }

    //     let publish_update = true;
    //     // Keep the initial state to pass to a transition callback
    //     let initial_state = state_machine.current_state;
    //     // SAFETY: The state machine has been checked to be initialized by this point, and is
    //     // therefore not null. As for the pointer cast, it's as safe as the rclcpp version. A
    //     // better method of handling state will probably need to be devised later on, though.
    //     let initial_state =
    //         unsafe { &State::from_raw(initial_state as *mut rcl_lifecycle_state_s) };

    //     // SAFETY: The state machine has been checked to be initialized by this point
    //     unsafe {
    //         rcl_lifecycle_trigger_transition_by_id(
    //             &mut *state_machine,
    //             transition_id,
    //             publish_update,
    //         )
    //         .ok()?
    //     };

    //     let get_label_for_return_code = |cb_return_code: &Transition| {
    //         let cb_id = cb_return_code.id;
    //         if cb_id == Transition::TRANSITION_CALLBACK_SUCCESS {
    //             "transition_success"
    //         } else if cb_id == Transition::TRANSITION_CALLBACK_FAILURE {
    //             "transition_failure"
    //         } else {
    //             "transition_error"
    //         }
    //     };

    //     // SAFETY: The state machine is not null, since it's initialized
    //     let cb_return_code =
    //         self.execute_callback(unsafe { (*state_machine.current_state).id }, initial_state);
    //     let transition_label = get_label_for_return_code(&cb_return_code);
    //     let transition_label_cstr = CString::new(transition_label).unwrap(); // Should be fine, since the strings are known to be valid CStrings

    //     // Safety: The state machine is not null, since it's initialized
    //     unsafe {
    //         rcl_lifecycle_trigger_transition_by_label(
    //             &mut *state_machine as *mut rcl_lifecycle_state_machine_s,
    //             transition_label_cstr.as_ptr(),
    //             publish_update,
    //         )
    //         .ok()?
    //     };

    //     Ok(cb_return_code)
    // }

    // fn execute_callback(&self, cb_id: u8, previous_state: &State) -> Transition {
    //     match cb_id {
    //         lifecycle_msgs::msg::State::TRANSITION_STATE_ACTIVATING => {
    //             let activate = self.on_activate.lock().unwrap();
    //             (activate)(previous_state)
    //         }
    //         lifecycle_msgs::msg::State::TRANSITION_STATE_CONFIGURING => {
    //             let configure = self.on_configure.lock().unwrap();
    //             (configure)(previous_state)
    //         }
    //         lifecycle_msgs::msg::State::TRANSITION_STATE_CLEANINGUP => {
    //             let cleanup = self.on_cleanup.lock().unwrap();
    //             (cleanup)(previous_state)
    //         }
    //         lifecycle_msgs::msg::State::TRANSITION_STATE_DEACTIVATING => {
    //             let deactivate = self.on_deactivate.lock().unwrap();
    //             (deactivate)(previous_state)
    //         }
    //         lifecycle_msgs::msg::State::TRANSITION_STATE_SHUTTINGDOWN => {
    //             let shutdown = self.on_shutdown.lock().unwrap();
    //             (shutdown)(previous_state)
    //         }
    //         _ => {
    //             let error_handling = self.on_error.lock().unwrap();
    //             (error_handling)(previous_state)
    //         }
    //     }
    // }

    // fn trigger_transition_by_label(&mut self, transition_label: &str) -> Result<State, RclrsError> {
    //     let transition = {
    //         // Make sure that the state machine is initialized before doing anything
    //         let state_machine = self.state_machine.lock().unwrap();
    //         // SAFETY: No preconditions for this function
    //         unsafe {
    //             rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
    //         }

    //         let c_transition_label = CString::new(transition_label).unwrap(); // This should be fine as the label originated from C
    //                                                                           // SAFETY: No preconditions for this function
    //         unsafe {
    //             rcl_lifecycle_get_transition_by_label(
    //                 state_machine.current_state,
    //                 c_transition_label.as_ptr(),
    //             )
    //         }
    //     };

    //     if !transition.is_null() {
    //         // SAFETY: We have just confirmed this is not null
    //         let transition_id = unsafe { (*transition).id as u8 };
    //         self.change_state(transition_id)?;
    //     }
    //     self.get_current_state()
    // }

    // fn trigger_transition_by_id(&mut self, transition_id: u8) -> Result<State, RclrsError> {
    //     self.change_state(transition_id)?;
    //     self.get_current_state()
    // }

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

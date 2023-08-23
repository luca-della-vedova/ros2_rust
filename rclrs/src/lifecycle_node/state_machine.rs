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

use std::{sync::Mutex, ffi::{CString, CStr}, thread::current};

use crate::{rcl_bindings::*, vendor::lifecycle_msgs::{srv::{ChangeState_Request, ChangeState_Response, GetState_Request, GetState_Response, GetAvailableStates_Request, GetAvailableStates_Response, GetAvailableTransitions_Request, GetAvailableTransitions_Response}, self, msg::Transition}, ToResult, RclrsError};

use super::{LifecycleCallback, state::State, transition};

pub(crate) struct LifecycleMachine {
    pub state_machine: Mutex<rcl_lifecycle_state_machine_t>,
    pub on_activate: Mutex<LifecycleCallback>,
    pub on_cleanup: Mutex<LifecycleCallback>,
    pub on_configure: Mutex<LifecycleCallback>,
    pub on_deactivate: Mutex<LifecycleCallback>,
    pub on_shutdown: Mutex<LifecycleCallback>,
    pub on_error: Mutex<LifecycleCallback>,
}

impl LifecycleMachine {
    pub(crate) fn on_change_state(
        &self,
        _header: &rmw_request_id_t,
        req: &ChangeState_Request,
    ) -> ChangeState_Response {
        let mut resp = ChangeState_Response::default();
        let transition_id = {
            let state_machine = &*self.state_machine.lock().unwrap();
            // SAFETY: No preconditions for this function
            unsafe {
                rcl_lifecycle_state_machine_is_initialized(state_machine)
                .ok()
                .unwrap()
            };
            let mut transition_id = req.transition.id;

            // If there's a label attached to the request, we check the transition attached to this label.
            // We can't compare the id of the looked up transition any further because ROS 2 service call
            // sets all integers to zero by default. That means if we call ROS 2 service call:
            // ... {transition: {label: shutdown}}
            // the id of the request is 0 (zero) whereas the id from the looked up transition can be different.
            // The result of this is that the label takes precedence over the ID.
            if !req.transition.label.is_empty() {
                // This should be safe to unwrap, since the label originated in C/C++
                let label_cstr = CString::new(req.transition.label.clone()).unwrap();
                // SAFETY: No preconditions for this function - however, it may return null
                let rcl_transition = unsafe {
                    rcl_lifecycle_get_transition_by_label(
                        state_machine.current_state,
                        label_cstr.as_ptr(),
                    )
                };
                if rcl_transition.is_null() {
                    resp.success = false;
                    return resp;
                }
                // SAFETY: We already checked to make sure this wasn't null
                transition_id = unsafe { (*rcl_transition).id as u8};
            }
            transition_id
        };

        let ret = self.change_state(transition_id).unwrap();
        resp.success = ret.id == lifecycle_msgs::msg::Transition::TRANSITION_CALLBACK_SUCCESS;

        resp
    }

    pub(crate) fn on_get_state(
        &self,
        _header: &rmw_request_id_t,
        _req: &GetState_Request,
    ) -> GetState_Response {
        let state_machine = &*self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function.
        unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok().unwrap() };

        // SAFETY: The state machine has been confirmed to be initialized by this point, so the
        // label pointer should not be null
        let label = unsafe {
            CStr::from_ptr((*state_machine.current_state).label)
                .to_owned()
                .to_string_lossy()
                .to_string()
        };
        // SAFETY: The state machine has been confirmed to be initialized by this point, so the id
        // pointer should not be null.
        let id = unsafe { (*state_machine.current_state).id };
        let current_state = lifecycle_msgs::msg::State { id, label };

        GetState_Response { current_state }
    }

    pub(crate) fn on_get_available_states(
        &self,
        _header: &rmw_request_id_t,
        _req: &GetAvailableStates_Request,
    ) -> GetAvailableStates_Response {
        let state_machine = &*self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function.
        unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok().unwrap() };

        let mut available_states = Vec::<lifecycle_msgs::msg::State>::new();
        for i in 0..state_machine.transition_map.states_size as isize {
            // SAFETY: The state machien has been confirmed to be initialized by this point, so the
            // label pointer should not be null
            let label = unsafe {
                CStr::from_ptr((*state_machine.transition_map.states.offset(i)).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string()
            };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so the
            // id pointer should not be null
            let id = unsafe { (*state_machine.transition_map.states.offset(i)).id };
            let available_state = lifecycle_msgs::msg::State { id, label };
            available_states.push(available_state);
        }

        GetAvailableStates_Response { available_states }

    }

    pub(crate) fn on_get_available_transitions(
        &self,
        _header: &rmw_request_id_t,
        _req: &GetAvailableTransitions_Request,
    ) -> GetAvailableTransitions_Response {
        let state_machine = &*self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function.
        unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok().unwrap() };

        let mut available_transitions = Vec::<lifecycle_msgs::msg::TransitionDescription>::new();
        // SAFETY: The state machine has been confirmed to be initialized by this point, so the
        // transition size should not be null
        let valid_transition_size =
            unsafe { (*state_machine.current_state).valid_transition_size as isize };
        for i in 0..valid_transition_size {
            // SAFETY: The state machine has been confirmed to be initialized by this point, so the
            // transition pointer should not be null
            let rcl_transition =
                unsafe { (*state_machine.current_state).valid_transitions.offset(i) };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so
            // the transition pointer should not be null
            let transition = unsafe {
                let transition_id = (*rcl_transition).id as u8;
                let transition_label = CStr::from_ptr((*rcl_transition).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string();
                lifecycle_msgs::msg::Transition {
                    id: transition_id,
                    label: transition_label,
                }
            };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so
            // the start state pointer should not be null
            let start_state = unsafe {
                let start_state_id = (*(*rcl_transition).start).id;
                let start_state_label = CStr::from_ptr((*(*rcl_transition).start).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string();
                lifecycle_msgs::msg::State {
                    id: start_state_id,
                    label: start_state_label,
                }
            };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so
            // the goal state pointer should not be null
            let goal_state = unsafe {
                let goal_state_id = (*(*rcl_transition).goal).id;
                let goal_state_label = CStr::from_ptr((*(*rcl_transition).goal).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string();
                lifecycle_msgs::msg::State {
                    id: goal_state_id,
                    label: goal_state_label,
                }
            };
            let trans_desc = lifecycle_msgs::msg::TransitionDescription {
                transition,
                start_state,
                goal_state,
            };
            available_transitions.push(trans_desc);
        }
        lifecycle_msgs::srv::GetAvailableTransitions_Response {
            available_transitions,
        }
    }

    pub(crate) fn on_get_transition_graph(
        &self,
        _header: &rmw_request_id_t,
        _req: &GetAvailableTransitions_Request,
    ) -> GetAvailableTransitions_Response {
        let state_machine = &*self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function.
        unsafe { rcl_lifecycle_state_machine_is_initialized(state_machine).ok().unwrap() };

        let mut available_transitions = Vec::<lifecycle_msgs::msg::TransitionDescription>::new();
        
        let valid_transition_size =
             state_machine.transition_map.transitions_size as isize;
        for i in 0..valid_transition_size {
            // SAFETY: The state machine has been confirmed to be initialized by this point, so the
            // transition pointer should not be null
            let rcl_transition =
                unsafe { (state_machine.transition_map).transitions.offset(i) };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so
            // the transition pointer should not be null
            let transition = unsafe {
                let transition_id = (*rcl_transition).id as u8;
                let transition_label = CStr::from_ptr((*rcl_transition).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string();
                lifecycle_msgs::msg::Transition {
                    id: transition_id,
                    label: transition_label,
                }
            };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so
            // the start state pointer should not be null
            let start_state = unsafe {
                let start_state_id = (*(*rcl_transition).start).id;
                let start_state_label = CStr::from_ptr((*(*rcl_transition).start).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string();
                lifecycle_msgs::msg::State {
                    id: start_state_id,
                    label: start_state_label,
                }
            };
            // SAFETY: The state machine has been confirmed to be initialized by this point, so
            // the goal state pointer should not be null
            let goal_state = unsafe {
                let goal_state_id = (*(*rcl_transition).goal).id;
                let goal_state_label = CStr::from_ptr((*(*rcl_transition).goal).label)
                    .to_owned()
                    .to_string_lossy()
                    .to_string();
                lifecycle_msgs::msg::State {
                    id: goal_state_id,
                    label: goal_state_label,
                }
            };
            let trans_desc = lifecycle_msgs::msg::TransitionDescription {
                transition,
                start_state,
                goal_state,
            };
            available_transitions.push(trans_desc);
        }
        lifecycle_msgs::srv::GetAvailableTransitions_Response {
            available_transitions,
        }
    }

    pub(crate) fn get_current_state(&self) -> Result<State, RclrsError> {
        // Make sure that the state machine is initialized before doing anything
        let state_machine = self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function
        unsafe {
            rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
        }

        // SAFETY: The state machine has been confirmed to be initialized by this point, so the
        // pointer should not be null
        let current_state =
            unsafe { State::from_raw(state_machine.current_state as *mut rcl_lifecycle_state_s) };
        Ok(current_state)
    }

    pub(crate) fn get_available_states(&self) -> Result<Vec<State>, RclrsError> {
        // Make sure that the state machine is initialized before doing anything
        let state_machine = self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function
        unsafe {
            rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
        }

        let mut states = Vec::<State>::new();

        let states_size = state_machine.transition_map.states_size as isize;
        for i in 0..states_size {
            // SAFETY: The state machine has been confirmed to be initialized by this point, so the
            // pointer should not be null
            let available_state =
                unsafe { State::from_raw(state_machine.transition_map.states.offset(i)) };
            states.push(available_state)
        }

        Ok(states)
    }

    pub(crate) fn get_available_transitions(&self) -> Result<Vec<transition::Transition>, RclrsError> {
        // Make sure that the state machine is initialized before doing anything
        let state_machine = self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function
        unsafe {
            rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
        }

        let mut transitions = Vec::<transition::Transition>::new();

        // SAFETY: The state machine has been confirmed to be initialized at this point, so the
        // pointer should not be null
        let transitions_size =
            unsafe { (*state_machine.current_state).valid_transition_size as isize };
        for i in 0..transitions_size {
            // SAFETY: The state machine has been confirmed to be initialized at this point, so the
            // pointer should not be null
            let available_transition = unsafe {
                transition::Transition::from_raw(
                    (*state_machine.current_state).valid_transitions.offset(i),
                )
            };
            transitions.push(available_transition)
        }

        Ok(transitions)
    }

    pub(crate) fn get_transition_graph(&self) -> Result<Vec<transition::Transition>, RclrsError> {
        // Make sure that the state machine is initialized before doing anything
        let state_machine = self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function
        unsafe {
            rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
        }

        let mut transitions = Vec::<transition::Transition>::new();

        // SAFETY: The state machine has been confirmed to be initialized at this point, so the
        // pointer should not be null
        let transitions_size = state_machine.transition_map.transitions_size as isize;
        for i in 0..transitions_size {
            // SAFETY: The state machine has been confirmed to be initialized at this point, so the pointer should not be null
            let available_transition = unsafe {
                transition::Transition::from_raw(state_machine.transition_map.transitions.offset(i))
            };
            transitions.push(available_transition);
        }

        Ok(transitions)
    }

    pub(crate) fn change_state(&self, transition_id: u8) -> Result<Transition, RclrsError> {
        // Make sure that the state machine is initialized before doing anything
        let mut state_machine = self.state_machine.lock().unwrap();
        // SAFETY: No preconditions for this function
        unsafe {
            rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
        }
        
        let publish_update = true;
        // Keep the initial state to pass to a transition callback
        let initial_state = state_machine.current_state;
        // SAFETY: The state machine has been checked to be initialized by this point, and is
        // therefore not null. As for the pointer cast, it's as safe as the rclcpp version. A
        // better method of handling state will probably need to be devised later on, though.
        let initial_state =
            unsafe { &State::from_raw(initial_state as *mut rcl_lifecycle_state_s) };

        // SAFETY: The state machine has been checked to be initialized by this point
        unsafe {
            rcl_lifecycle_trigger_transition_by_id(
                &mut *state_machine,
                transition_id,
                publish_update
            )
            .ok()?
        };

        let get_label_for_return_code = |cb_return_code: &Transition| {
            let cb_id = cb_return_code.id;
            if cb_id == Transition::TRANSITION_CALLBACK_SUCCESS {
                "transition_success"
            } else if cb_id == Transition::TRANSITION_CALLBACK_FAILURE {
                "transition_failure"
            } else {
                "transition_error"
            }
        };

        // SAFETY: The state machine is not null, since it's initialized
        let cb_return_code =
            self.execute_callback(unsafe { (*state_machine.current_state).id }, initial_state);
        let transition_label = get_label_for_return_code(&cb_return_code);
        let transition_label_cstr = CString::new(transition_label).unwrap(); // Should be fine, since the strings are known to be valid CStrings

        // SAFETY: The state machine is not null, since it's initialized
        unsafe {
            rcl_lifecycle_trigger_transition_by_label(
                &mut *state_machine as *mut rcl_lifecycle_state_machine_s,
                transition_label_cstr.as_ptr(),
                publish_update
            )
            .ok()?
        };

        Ok(cb_return_code)
    }

    fn execute_callback(&self, cb_id: u8, previous_state: &State) -> Transition {
        match cb_id {
            lifecycle_msgs::msg::State::TRANSITION_STATE_ACTIVATING => {
                let activate = self.on_activate.lock().unwrap();
                (activate)(previous_state)
            }
            lifecycle_msgs::msg::State::TRANSITION_STATE_CLEANINGUP => {
                let cleanup = self.on_cleanup.lock().unwrap();
                (cleanup)(previous_state)
            }
            lifecycle_msgs::msg::State::TRANSITION_STATE_CONFIGURING => {
                let configure = self.on_configure.lock().unwrap();
                (configure)(previous_state)
            }
            lifecycle_msgs::msg::State::TRANSITION_STATE_DEACTIVATING => {
                let deactivate = self.on_deactivate.lock().unwrap();
                (deactivate)(previous_state)
            }
            lifecycle_msgs::msg::State::TRANSITION_STATE_SHUTTINGDOWN => {
                let shutdown = self.on_shutdown.lock().unwrap();
                (shutdown)(previous_state)
            }
            _ => {
                let error_handling = self.on_error.lock().unwrap();
                (error_handling)(previous_state)
            }
        }
    }

    fn trigger_transition_by_label(&mut self, transition_label: &str) -> Result<State, RclrsError> {
        let transition = {
            // Make sure that the state machine is initialized before doing anything
            let state_machine = self.state_machine.lock().unwrap();
            // SAFETY: No preconditions for this function
            unsafe {
                rcl_lifecycle_state_machine_is_initialized(&*state_machine).ok()?;
            }

            let c_transition_label = CString::new(transition_label).unwrap();   // This should be fine as the label originated from C/C++

            // SAFETY: No preconditions for this function
            unsafe {
                rcl_lifecycle_get_transition_by_label(
                    state_machine.current_state,
                    c_transition_label.as_ptr(),
                )
            }
        };

        if !transition.is_null() {
            // SAFETY: We have just confirmed this is not null
            let transition_id = unsafe { (*transition).id as u8};
            self.change_state(transition_id)?;
        }
        self.get_current_state()
    }

    fn trigger_transition_by_id(&mut self, transition_id: u8) -> Result<State, RclrsError> {
        self.change_state(transition_id)?;
        self.get_current_state()
    }
}
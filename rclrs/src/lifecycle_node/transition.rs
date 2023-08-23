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

use std::{sync::{Arc, Mutex}, ffi::{CString, c_void, CStr}, mem::size_of, ptr::{null, null_mut}};

use crate::{rcl_bindings::*, RclrsError, ToResult, RclReturnCode};

use super::state::State;

pub struct Transition {
    id: u8,
    label: String,
    start: Option<State>,
    goal: Option<State>,
    allocator: rcutils_allocator_t,
    transition_handle: Arc<Mutex<*mut rcl_lifecycle_transition_t>>,
}

impl Drop for Transition {
    fn drop(&mut self) {
        self.reset().unwrap();
    }
}

impl Transition {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(id: u8, label: &str) -> Result<Transition, RclrsError> {
        let transition_label =
            CString::new(label).map_err(|err| RclrsError::StringContainsNul {
                err,
                s:label.to_owned(),
            })?;
        
        // SAFETY: Getting the default allocator for RCL should be safe
        let allocator = unsafe { rcutils_get_default_allocator() };

        unsafe {
            let transition_handle = allocator.allocate.unwrap()(size_of::<rcl_lifecycle_transition_t>(), allocator.state);
            // SAFETY: We hav already allocated the proper amount of space in the previous instruction
            let transition_handle = std::mem::transmute::<*mut c_void, *mut rcl_lifecycle_transition_t>(transition_handle);

            if transition_handle.is_null() {
                return Err(RclrsError::RclError {
                    code: RclReturnCode::BadAlloc,
                    msg: None,
                })
            };
            
            // SAFETY: transition_handle has already been allocated by this point, and has been checked to be non-null
            rcl_lifecycle_transition_init(
                transition_handle,
                id as u32,
                transition_label.as_c_str().as_ptr(),
                null_mut(),
                null_mut(),
                &allocator).ok()?;
        
            Ok(Transition {
                id,
                label: label.to_owned(),
                start: None,
                goal: None,
                allocator,
                transition_handle: Arc::new(Mutex::new(transition_handle))})
        }

    }

    // Creates a new [`Transition`] object from a raw pointer to an [`rcl_lifecycle_transition_t`] object.
    // SAFETY: `rcl_lifecycle_transition_handle must not be null
    pub unsafe fn from_raw(rcl_lifecycle_transition_handle: *mut rcl_lifecycle_transition_t) -> Self {
        // SAFETY: Getting the default allocator for RCL should be safe
        let allocator = rcutils_get_default_allocator();
        // SAFETY: rcl_lifecycle_transition_handle must not be null - see safety comment for the function
        let label = CStr::from_ptr((*rcl_lifecycle_transition_handle).label).to_owned().to_string_lossy().to_string();
        // SAFETY: rcl_lifecycle_transition_handle must not be null - see safety comment for the function
        let id = (*rcl_lifecycle_transition_handle).id as u8;
        // SAFETY: rcl_lifecycle_transition_handle must not be null - see safety comment for the function
        let start = {
            let raw_start = (*rcl_lifecycle_transition_handle).start;
            if raw_start.is_null() {
                None
            } else {
                // SAFETY: We have just checked for null, this is safe to use
                let start = State::from_raw(raw_start);
                Some(start)
            }
        };
        // SAFETY: rcl_lifecycle_transition_handle must not be null - see safety comment for the function
        let goal = {
            let raw_goal = (*rcl_lifecycle_transition_handle).goal;
            if raw_goal.is_null() {
                None
            } else {
                // SAFETY: We have just checked for null, this is safe to use
                let goal = State::from_raw(raw_goal);
                Some(goal)
            }
        };
        Self {
            id,
            label,
            start,
            goal,
            allocator,
            transition_handle: Arc::new(Mutex::new(rcl_lifecycle_transition_handle)),
        }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn label(&self) -> &str {
        self.label.as_ref()
    }

    pub fn start(&self) -> Option<&State> {
        self.start.as_ref()
    }

    pub fn goal(&self) -> Option<&State> {
        self.goal.as_ref()
    }

    fn reset(&mut self) -> Result<(), RclrsError> {
        let transition_handle = self.transition_handle.lock().unwrap();

        if transition_handle.is_null() {
            return Ok(());
        }
        
        // SAFETY: By this point, we should have confirmed that transition_handle still exists
        unsafe {
            rcl_lifecycle_transition_fini(transition_handle.as_mut().unwrap(), &self.allocator).ok()?;
        }

        Ok(())
    }
}

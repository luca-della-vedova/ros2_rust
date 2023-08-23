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

use std::{
    ffi::{c_void, CStr, CString},
    mem::size_of,
    sync::{Arc, Mutex},
};

use crate::{error::ToResult, rcl_bindings::*, RclReturnCode, RclrsError};

pub struct State {
    id: u8,
    label: String,
    allocator: rcutils_allocator_t,
    state_handle: Arc<Mutex<*mut rcl_lifecycle_state_t>>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.reset().unwrap();
    }
}

impl State {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(id: u8, label: &str) -> Result<State, RclrsError> {
        let state_label = CString::new(label).map_err(|err| RclrsError::StringContainsNul {
            err,
            s: label.to_owned(),
        })?;

        // SAFETY: Getting the default allocator for RCL should be safe
        let allocator = unsafe { rcutils_get_default_allocator() };

        unsafe {
            let state_handle =
                allocator.allocate.unwrap()(size_of::<rcl_lifecycle_state_t>(), allocator.state);
            // SAFETY: We have already allocated the proper amount of space in the previous instruction
            let state_handle =
                std::mem::transmute::<*mut c_void, *mut rcl_lifecycle_state_t>(state_handle);

            if state_handle.is_null() {
                return Err(RclrsError::RclError {
                    code: RclReturnCode::BadAlloc,
                    msg: None,
                });
            };

            // SAFETY: state_handle has already been allocated by this point, and has been checked to be non-null
            rcl_lifecycle_state_init(
                state_handle,
                id,
                state_label.as_c_str().as_ptr(),
                &allocator,
            )
            .ok()?;
            Ok(State {
                id,
                label: state_label.to_string_lossy().to_string(),
                allocator,
                state_handle: Arc::new(Mutex::new(state_handle)),
            })
        }
    }

    // Creates a new [`State`] object from a raw pointer to an [`rcl_lifecycle_state_t`] object.
    // SAFETY: `rcl_lifecycle_state_handle` must not be null
    pub unsafe fn from_raw(rcl_lifecycle_state_handle: *mut rcl_lifecycle_state_t) -> Self {
        // SAFETY: Getting the default allocator for RCL should be safe
        let allocator = rcutils_get_default_allocator();
        // SAFETY: rcl_lifecycle_state_handle must not be null - see safety comment for the function
        let label = CStr::from_ptr((*rcl_lifecycle_state_handle).label).to_owned();
        Self {
            // SAFETY: rcl_lifecycle_state_handle must not be null - see safety comment for the function
            id: (*rcl_lifecycle_state_handle).id,
            label: label.to_string_lossy().to_string(),
            allocator,
            state_handle: Arc::new(Mutex::new(rcl_lifecycle_state_handle)),
        }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn label(&self) -> &str {
        self.label.as_ref()
    }

    pub fn reset(&mut self) -> Result<(), RclrsError> {
        let state_handle = self.state_handle.lock().unwrap();

        if state_handle.is_null() {
            return Ok(());
        }

        // SAFETY: By this point, we should have confirmed that state_handle still exists
        unsafe {
            rcl_lifecycle_state_fini(state_handle.as_mut().unwrap(), &self.allocator).ok()?;
        }

        Ok(())
    }
}

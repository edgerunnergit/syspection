#![no_std]
#![no_main]

use aya_bpf::{
    helpers::*,
    macros::tracepoint, 
    programs::TracePointContext
    };

#[tracepoint(name = "syspection")]
pub fn syspection(ctx: TracePointContext) -> i32 {
    match unsafe {try_syspection(&ctx)} {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_syspection(ctx: &TracePointContext) -> Result<i32, i64> {

    // Get the process that is executing the command
    let mut exec_buf = [0u8; 16];
    let exec = bpf_get_current_comm().unwrap_or_default();

    // Get the command that is being executed and stores it in exec_comm
    let exec_comm = ctx.read_at::<*const u8>(16)?;
    _ = bpf_probe_read_user_str_bytes(exec_comm, &mut exec_buf);

    // Create a buffer for the arguments of the command
    let mut arg_buf = [[0u8; 32]; 10];
    
    // Get the arguments of the command
    let argv = ctx.read_at::<*const *const u8>(24)?;
    for i in 0..10 {
        let arg_ptr = bpf_probe_read_user(argv.offset(i))?;

        if arg_ptr.is_null() {
            break;
        }

        bpf_probe_read_user_str_bytes(arg_ptr, &mut arg_buf[i as usize]).unwrap_or_default();
    }


    bpf_printk!(b"exec: %s: %s %s %s %s", exec.as_ptr(), exec_comm, arg_buf[1].as_ptr(), arg_buf[2].as_ptr(), arg_buf[3].as_ptr());
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

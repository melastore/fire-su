use aya::{maps::ProgramArray, programs::{CgroupSkb, ProgramFd}};
fn test(prog_array: &mut ProgramArray<aya::maps::MapData, u32>, fd: ProgramFd) {
    prog_array.set(0, fd, 0);
}

import angr
import claripy


def phase1():
    start = 0x400ee0
    target = 0x400ef7
    avoids = [0x40143a]

    prj = angr.Project('bomb', auto_load_libs=False)
    prj.hook(0x401338, angr.SIM_PROCEDURES['libc']['strcmp']())

    sym_var = claripy.BVS('sym_input', 100 * 8);
    print 2
    print sym_var
    state = prj.factory.call_state(start, sym_var)

    sm = prj.factory.simgr(state)
    sm.explore(find=target, avoid=avoids)

    if sm.found:
        found = sm.found[0]
        flag = found.state.se.eval(sym_var, cast_to=str)
        print flag


def main():
    phase1()


if __name__ == "__main__":
    main()

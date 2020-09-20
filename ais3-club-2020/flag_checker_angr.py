#!/usr/bin/env python

import angr
import claripy

p = angr.Project('flag_checker')
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)
sm.explore(find=0x401204, avoid=0x401213)
# sm.run()

print(len(sm.found))
print(sm.found[0].posix.dumps(0))

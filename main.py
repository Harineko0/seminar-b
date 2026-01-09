from tinyvm import CPUState, execute_instruction

def main():
    state = CPUState(regs=[0]*16, pc=0, sr={f:False for f in "ZNCVPH"}, memory=bytearray(1024))
    # Test ADDC: R1 = R2 + R3 + Carry
    # Example binary instruction encoding for Nebula-32
    inst = 0x1A012300 
    execute_instruction(state, inst)
    print(f"PC: {state.pc}, R1: {state.regs[1]}, SR: {state.sr}")

if __name__ == "__main__":
    main()

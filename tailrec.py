import dis, types

def unpack_op(bytecode): 
    '''Unpacks the offset, opcode and opaarg for each pair of bytes in the bytecode.
    
    Parameters
    =========================================
    bytecode (bytes): the bytecode of a code object
    
    Generates
    =========================================
    tuple: a tuple of offset, opcode and oparg for each pair of bytes in the bytecode
    '''
    extended_arg = 0
    for i in range(0, len(bytecode), 2):
        opcode = bytecode[i]
        if opcode >= dis.HAVE_ARGUMENT:
            oparg = bytecode[i+1] | extended_arg
            extended_arg = (oparg << 8) if opcode == dis.EXTENDED_ARG else 0
        else:
            oparg = None
        yield (i, opcode, oparg)

def find_linestarts(codeobj):
    """Finds the offsets in a bytecode which are the start a line in the source code.
    Parameters
    =========================================
    codeobj (code): code object
    
    Returns
    =========================================
    dict: a dictionary with offsets as the keys and their line numbers as their values of offsets
    """
    byte_increments = codeobj.co_lnotab[0::2]
    line_increments = codeobj.co_lnotab[1::2]
    byte = 0
    line = codeobj.co_firstlineno
    linestart_dict = {byte: line}      
    for byte_incr, line_incr in zip(byte_increments,
                                    line_increments):
        byte += byte_incr
        if line_incr >= 0x80:
            line_incr -= 0x100
        line += line_incr
        linestart_dict[byte]=line
    return linestart_dict


def get_argvalue(offset, codeobj, opcode, oparg):
    '''Finds the human friendly meaning of each oparg in an instruction.
    
    Parameters
    =========================================
    offset (int): offset of the instruction
    codeobj (code): code object
    opcode (int): opcode of the instruction
    oparg (int): oparg of the instruction
    
    Returns
    =========================================
    argval: the human friendly meaning of the oparg in an instruction. 
    '''
    constants= codeobj.co_consts
    varnames = codeobj.co_varnames
    names = codeobj.co_names
    cell_names = codeobj.co_cellvars + codeobj.co_freevars
    argval = None
    if opcode in dis.hasconst:
        if constants is not None:
            argval = constants[oparg]
            if type(argval)==str or argval==None:
                 argval = repr(argval)
    elif opcode in dis.hasname:
        if names is not None:
            argval = names[oparg]
    elif opcode in dis.hasjrel:
        argval = offset + 2 + oparg
        argval = "to " + repr(argval)
    elif opcode in dis.haslocal:
        if varnames is not None:
            argval = varnames[oparg]
    elif opcode in dis.hascompare:
        argval = dis.cmp_op[oparg]
    elif opcode in dis.hasfree:
        if cell_names is not None:
            argval = cell_names[oparg]
    return argval


def findlabels(codeobj):
    '''Finds all the offsets in the bytecode which are jump targets.
    
    Parameters
    =========================================
    codeobj (code): code object
    
    Returns
    =========================================
    list: list of offsets
    '''
    bytecode = codeobj.co_code
    labels = []
    for offset, opcode, oparg in unpack_op(bytecode):
            if opcode in dis.hasjrel:
                label = offset + 2 + oparg
            elif opcode in dis.hasjabs:
                label = oparg
            else:
                continue
            if label not in labels:
                labels.append(label)
    return labels


def disassemble(c): 
    '''Disassebmles and prints the bytecode of a code object.
    
    Parameters
    =========================================
    c (code): code object        
    '''    
    if not(hasattr(c, 'co_code')):
        raise TypeError("The argument should be a code object")
    code_objects = []
    linestarts = find_linestarts(c)
    labels = findlabels(c)
    bytecode = c.co_code
    extended_arg = 0
    for offset, opcode, oparg in unpack_op(bytecode):
        argvalue = get_argvalue(offset, c, opcode, oparg)
        if hasattr(argvalue, 'co_code'):
            code_objects.append(argvalue)
        line_start = linestarts.get(offset, None)
        dis_text =  "{0:4}{1:2}{2:5} {3:<22} {4:3} {5}".format(str(line_start or ''),                                                        
                                                        ">>" if offset in labels else "",
                                                        offset, dis.opname[opcode],                                                             
                                                        oparg if oparg is not None else '',
                                                        "(" + str(argvalue) + ")" if argvalue is not 
                                                                                        None else '')                                                   
        if (line_start and offset):
            print() 
        print(dis_text)
    for oc in code_objects:
        print("\nDisassembly of{}:\n".format(oc))
        disassemble(oc)


def disassemble_to_list(c):
    '''Disassebmles the bytecode of a code object and returns the result as a list.
    
    Parameters
    =========================================
    c (code): code object    
    
    Returns
    =========================================
    list: disassembled bytecode instructions
    '''     
    code_list = []
    bytecode = c.co_code
    for offset, opcode, oparg in unpack_op(bytecode):
        argval = get_argvalue(offset, c, opcode, oparg)
        if argval is not None:
            if type(argval)==str:
                argval = argval.strip("\'")
            argval = None if argval=='None' else argval
            code_list.append([dis.opname[opcode], argval])
        else:
            if oparg is not None:
                code_list.append([dis.opname[opcode], oparg])
            else:
                code_list.append([dis.opname[opcode]])              
    return code_list


def get_oparg(offset, opcode, argval, constants, varnames, names, cell_names):
    '''Finds the oparg of an instruction based on its human friendly meaning.
    
    Parameters
    =========================================
    offset (int): offset of the instruction
    opcode (int): opcode of the instruction
    argval: human friendly meaning of the oparg
    constants (tuple): co_consts attribute of the code object
    varnames (tuple): co_varnames attribute of the code object
    names (tuple): co_names attribute of the code object
    cell_names (tuple): co_freevars + co_cellvars attributes of the code object
    
    Returns
    =========================================
    int: the oparg of the instruction 
    '''
    oparg = argval
    if opcode in dis.hasconst:
        if constants is not None:
            oparg = constants.index(argval)
    elif opcode in dis.hasname:
        if names is not None:
            oparg = names.index(argval)
    elif opcode in dis.hasjrel:
        argval = int(argval.split()[1])
        oparg = argval - offset - 2 
    elif opcode in dis.haslocal:
        if varnames is not None:
            oparg = varnames.index(argval)
    elif opcode in dis.hascompare:
        oparg = dis.cmp_op.index(argval)
    elif opcode in dis.hasfree:
        if cell_names is not None:
            oparg = cell_names.index(argval)
    return oparg


def assemble(code_list, constants, varnames, names, cell_names):
    '''Assembles the bytecode list into a bytes literal.
    
    Parameters
    =========================================
    code_list (list): disassembled bytecode list
    constants (tuple): co_consts attribute of the code object
    varnames (tuple): co_varnames attribute of the code object
    names (tuple): co_names attribute of the code object
    cell_names (tuple): co_freevars + co_cellvars attributes of the code object
    
    Returns
    =========================================
    bytes: the bytes literal of the disassembled bytescode list
    '''
    byte_list = []
    for i, instruction in enumerate(code_list):
        if len(instruction)==2:
            opname, argval = instruction
            opcode = dis.opname.index(opname)
            oparg = get_oparg(i*2, opcode, argval, constants, varnames, names, cell_names)
        else:
            opname = instruction[0]
            opcode = dis.opname.index(opname)
            oparg = 0    
        byte_list += [opcode, oparg]  
    return(bytes(byte_list))


def tail_recursion(f):
    '''
    A decorator for the tail-call optimization of the target function.
    
    Parameters
    =========================================
    f (function): target function which should be tail-recursive
    
    Returns
    =========================================
    function: the input function with a new code object and modified bytecode which is tail-call optimized
    '''
    c = f.__code__
    disassembled_bytecode = disassemble_to_list(c)
    i = 0
    func_name = c.co_name
    while i < len(disassembled_bytecode):
        if disassembled_bytecode[i] == ['LOAD_GLOBAL', func_name]:
            tail_rec_flag = False
            for index, instruction in enumerate(disassembled_bytecode[i+1:]):
                # Recursive calls with positional-only arguments
                if (instruction[0] == "CALL_FUNCTION") and (disassembled_bytecode[i+index+2] == ["RETURN_VALUE"]):
                    args_count = instruction[1]
                    new_bytecode = [['STORE_FAST', var] for var in list(c.co_varnames)[args_count::-1]]
                    new_bytecode += [['POP_TOP'], ['JUMP_ABSOLUTE', 0]]
                    disassembled_bytecode[i+index+1:i+index+3] = new_bytecode
                    tail_rec_flag = True

                    # Updating the jump targets
                    for inst in disassembled_bytecode:
                        opcode = dis.opname.index(inst[0])
                        if opcode in dis.hasjrel:
                            jump_offset = int(inst[1].split("to")[1])
                            if jump_offset>(i+index+1)*2:
                                inst[1] = "to " + str((len(new_bytecode) - 2)*2 + jump_offset)
                        if opcode in dis.hasjabs:
                            if inst[1]>(i+index+1)*2:
                                inst[1] += (len(new_bytecode) - 2) * 2
                    
                    i += index + len(new_bytecode) + 1
                    break

                # Recursive calls with positional and keyword arguments
                elif (instruction[0] == "CALL_FUNCTION_KW") and (disassembled_bytecode[i+index+2] == ["RETURN_VALUE"]):
                    args_count = instruction[1]
                    kwargs_tuple = disassembled_bytecode[i+index][1] 
                    posargs_count = args_count - len(kwargs_tuple)
                    new_bytecode = [["POP_TOP"]]
                    new_bytecode += [['STORE_FAST', var] for var in list(kwargs_tuple)[len(kwargs_tuple)::-1]]
                    if posargs_count != 0:
                        new_bytecode += [['STORE_FAST', var] for var in list(c.co_varnames)[posargs_count-1::-1]]
                    new_bytecode += [['POP_TOP'], ['JUMP_ABSOLUTE', 0]]
                    disassembled_bytecode[i+index+1:i+index+3] = new_bytecode
                    tail_rec_flag = True

                    # Updating the jump targets
                    for inst in disassembled_bytecode:
                        opcode = dis.opname.index(inst[0])
                        if opcode in dis.hasjrel:
                            jump_offset = int(inst[1].split("to")[1])
                            if jump_offset>(i+index+1)*2:
                                inst[1] = "to " + str((len(new_bytecode) - 2)*2 + jump_offset)
                        if opcode in dis.hasjabs:
                            if inst[1]>(i+index+1)*2:
                                inst[1] += (len(new_bytecode) - 2) * 2
                    
                    i += index + len(new_bytecode) + 1             
                    break
            if tail_rec_flag == False:
                raise Exception("The decorated function is not tail-recursive")
        i += 1
    
    # Assembling the new bytecode
    new_co_code= assemble(disassembled_bytecode, c.co_consts,
                      c.co_varnames, c.co_names,
                      c.co_cellvars+c.co_freevars)

    # Creating a new code object
    nc = types.CodeType(c.co_argcount, c.co_kwonlyargcount,
                        c.co_nlocals, c.co_stacksize, c.co_flags,
                        new_co_code, c.co_consts, c.co_names, 
                        c.co_varnames, c.co_filename, c.co_name, 
                        c.co_firstlineno, c.co_lnotab, 
                        cellvars = c.co_cellvars, freevars = c.co_freevars)
    f.__code__ = nc
    
    return f
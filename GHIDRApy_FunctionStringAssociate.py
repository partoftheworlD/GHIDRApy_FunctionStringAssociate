# @category: Strings

import ghidra.app.script.GhidraScript
import ghidra.program.model.data.StringDataType as StringDataType
import exceptions

class Node:
    def __str__(self):
        raise NotImplementedError("Must sub-class")
    def indentedString(self, depth=0):
        raise NotImplementedError("")
    def __str__(self):
        return self.indentedString(depth=0)

class ReferenceNode(Node):
    def __init__(self, fromAddr, toAddr):
        self.fromAddr = fromAddr
        self.toAddr = toAddr
    def indentedString(self, depth=0):
        raise NotImplementedError("")

class StringNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr, string):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.string = string
    def __str__(self):
        return self.indentedString(depth=0)
    def indentedString(self, depth=0):
        string = "%s\n" % ( self.string)
        return string
    def hasString(self):
        return True

class FunctionNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.fn = getFunctionContaining(toAddr)
        self.references = []
    def hasString(self):
        for r in self.references:
            if isinstance(r, StringNode) or r.hasString():
                return True
        return False
    def ReplaceStringTrash(self, str):
            s = str.replace("\"", "")
            s = s.replace("ds", "")
            return s
    def indentedString(self, depth=0):
        string  = ""
        for r in self.references:
            if r.hasString():
                string  += "%s" % self.ReplaceStringTrash(r.indentedString(depth=depth+1))
        return string
    def getAddresses(self):
        return self.fn.getBody().getAddresses(True)
    def addReference(self, reference):
        rlist = []
        if not isinstance(reference, list):
            rlist.append(reference)
        for r in rlist:
            if not isinstance(r, ReferenceNode):
                raise ValueError("Must only add ReferenceNode type")
            else:
                self.references.append(r)
    def getName(self):
        if self.fn is not None:
            return self.fn.getName()
        else:
            return "fun_%s" % (self.toAddr)
    def process(self, processed=[]):
        if self.fn is None:
            return processed
        print "Processing -> %s" % (str(self.toAddr))
        if self.getName() in processed:
            return processed
        addresses = self.getAddresses()
        while addresses.hasNext():
            #for a in addresses:
            a = addresses.next()
            insn = getInstructionAt(a)
            if insn is not None:
                refs = getReferences(insn)
                for r in refs:
                    self.addReference(r)
        
        processed.append(self.getName())
        for r in self.references:
            if isinstance(r, FunctionNode):
                processed = r.process(processed=processed)
        return processed
    
class FunctionNotFoundException(exceptions.Exception):
    pass   

def getStringAtAddr(addr):
    """Get string at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()
        if isinstance(dt, StringDataType):
            return str(data)
    return None

def getStringReferences(insn):
    """Get strings referenced in any/all operands of an instruction, if present"""
    numOperands = insn.getNumOperands()
    found = []
    for i in range(numOperands):
        opRefs = insn.getOperandReferences(i)
        for o in opRefs:
            if o.getReferenceType().isData():
                string = getStringAtAddr(o.getToAddress())
                if string is not None:
                    found.append( StringNode(insn.getMinAddress(), o.getToAddress(), string) )
    return found

def getReferences(insn):
    refs = []
    refs += getStringReferences(insn)
    return refs

current_function = getFirstFunction()
while current_function is not None:
        if current_function is None:
                print "Please place the cursor within a function!"
        else:
                AddrSetView = current_function.getBody()
                func = FunctionNode(None, AddrSetView.getMinAddress())
                func.process()
                strings = func.indentedString()
                print str(strings)
                if len(strings) >= 1:
                        current_function.setRepeatableComment(str(strings))
                current_function = getFunctionAfter(current_function)

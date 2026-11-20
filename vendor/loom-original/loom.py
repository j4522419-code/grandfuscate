"""Loom: offline Luau AST -> register bytecode -> standalone Luau."""
import argparse
import json
import math
import os
from pathlib import Path
import random
import subprocess
import sys


class Unsupported(ValueError):
    pass


def reject(n, reason=None):
    raise Unsupported(f"{n['location']} (zero-based): {reason or n['type']} not supported")


BINARY = dict(Add='+', Sub='-', Mul='*', Div='/', FloorDiv='//', Mod='%', Pow='^', Concat='..', CompareEq='==', CompareNe='~=', CompareLt='<', CompareLe='<=', CompareGt='>', CompareGe='>=')
UNARY = dict(Minus='-', Len='#', Not='not ')
GLOBALS = {'workspace', 'game', 'print', 'type', 'tostring', 'tonumber', 'assert', 'select'}


class Function:
    def __init__(self, unit, parent=None):
        self.unit, self.parent = unit, parent
        unit.append(self)
        self.id = len(unit)
        self.code, self.constants, self.captures = [], [], []
        self.locals, self.outer = {}, {}
        self.nreg = self.nargs = 0

    def reg(self):
        self.nreg += 1
        return self.nreg

    def emit(self, op, *args):
        self.code.append([op, *args])
        return self.code[-1]

    def value(self, op, *args):
        r = self.reg()
        self.emit(op, r, *args)
        return r

    def const(self, v):
        if isinstance(v, float) and not math.isfinite(v):
            raise Unsupported('non-finite numeric literal')
        if isinstance(v, str) and '\ufffd' in v:
            raise Unsupported('binary/replacement-character literal cannot round-trip through AST JSON')
        # bool and number are distinct in Luau.
        for i, old in enumerate(self.constants, 1):
            if type(v) is type(old) and old == v:
                return i
        self.constants.append(v)
        return len(self.constants)

    def resolve(self, local):
        key = local['location']
        if key in self.locals:
            return 0, self.locals[key]
        if key not in self.outer:
            if not self.parent:
                reject(local, 'unresolved lexical binding')
            self.captures.append(self.parent.resolve(local))
            self.outer[key] = len(self.captures)
        return 1, self.outer[key]

    def bind(self, local, r):
        if local.get('isConst'): reject(local, 'const declaration')
        slot = len(self.locals) + 1
        self.locals[local['location']] = slot
        self.emit('BOX', slot, r)

    def listargs(self, nodes):
        # Last unparenthesized call expands. Preserve holes via explicit count.
        spread = bool(nodes and nodes[-1]['type'] == 'AstExprCall')
        regs = [self.expr(n, spread and i == len(nodes)-1) for i, n in enumerate(nodes)]
        return [int(spread), len(regs), *regs]

    def index(self, n):
        t = self.expr(n['expr'])
        k = (self.value('K', self.const(n['index'])) if n['type']=='AstExprIndexName' else self.expr(n['index']))
        return t, k

    def expr(self, n, packed=False):
        t = n['type'].removeprefix('AstExpr')
        if t in ('ConstantString','ConstantNumber','ConstantBool'): return self.value('K', self.const(n['value']))
        if t=='ConstantNil': return self.value('NIL')
        if t=='Local': return self.value('READ', *self.resolve(n['local']))
        if t=='Global':
            if n['global'] not in GLOBALS: reject(n, 'global '+n['global'])
            return self.value('GLOBAL', self.const(n['global']))
        if t in ('Group','TypeAssertion'): return self.expr(n['expr'])
        if t=='Unary' and n['op'] in UNARY: return self.value(n['op'], self.expr(n['expr']))
        if t=='Binary':
            a = self.expr(n['left']); op = n['op']
            if op in ('And','Or'):
                jump = self.emit('JF' if op=='And' else 'JT', a, 0)
                self.emit('MOVE', a, self.expr(n['right']))
                jump[-1] = len(self.code)+1
                return a
            if op in BINARY: return self.value(op, a, self.expr(n['right']))
        if t=='Function':
            if n['vararg'] or n.get('self'): reject(n, 'variadic or implicit-self function')
            child = Function(self.unit, self)
            child.nargs = len(n['args'])
            for arg in n['args']: child.bind(arg, child.reg())
            child.stat(n['body']); child.emit('RETURN',0,0)
            return self.value('CLOSURE',child.id)
        if t=='Call':
            if n['self']:
                target = n['func']
                if target['type'] != 'AstExprIndexName': reject(n,'computed method name')
                name = target['index']
                if not name.isascii() or not name.isidentifier(): reject(n,'non-identifier method')
                return self.value('METHOD:'+name, self.expr(target['expr']), int(packed), *self.listargs(n['args']))
            return self.value('CALL', self.expr(n['func']), int(packed), *self.listargs(n['args']))
        if t in ('IndexName','IndexExpr'): return self.value('GET', *self.index(n))
        if t=='Table':
            r = self.value('TABLE'); seq = 0
            for i,item in enumerate(n['items']):
                if item['kind']=='item':
                    if i+1==len(n['items']) and item['value']['type']=='AstExprCall': reject(n,'expanding table constructor')
                    seq+=1; k=self.value('K',self.const(seq))
                else: k=self.expr(item['key'])
                self.emit('SET',r,k,self.expr(item['value']))
            return r
        reject(n)

    def stat(self,n):
        t = n['type'].removeprefix('AstStat')
        if t=='Block':
            for s in n['body']: self.stat(s)
        elif t=='Local':
            if len(n['vars'])!=1 or len(n['values'])>1: reject(n,'parallel declaration')
            self.bind(n['vars'][0],self.expr(n['values'][0]) if n['values'] else self.value('NIL'))
        elif t=='LocalFunction':
            self.bind(n['name'],self.value('NIL')); self.emit('WRITE',*self.resolve(n['name']),self.expr(n['func']))
        elif t in ('Assign','CompoundAssign'):
            compound=t=='CompoundAssign'
            if not compound and (len(n['vars'])!=1 or len(n['values'])!=1): reject(n,'parallel assignment')
            var = n['var'] if compound else n['vars'][0]
            if var['type']=='AstExprLocal': read,write,addr='READ','WRITE',self.resolve(var['local'])
            elif var['type'] in ('AstExprIndexExpr','AstExprIndexName'): read,write,addr='GET','SET',self.index(var)
            else: reject(var,'assignment target')
            if compound:
                if n['op'] not in BINARY: reject(n)
                r=self.value(n['op'],self.value(read,*addr),self.expr(n['value']))
            else: r=self.expr(n['values'][0])
            self.emit(write,*addr,r)
        elif t=='Return': self.emit('RETURN',*self.listargs(n['list']))
        elif t=='Expr': self.expr(n['expr'])
        elif t in ('If','While'):
            start=len(self.code)+1
            j=self.emit('JF',self.expr(n['condition']),0)
            self.stat(n['body'] if t=='While' else n['thenbody'])
            if t=='While': self.emit('JMP',start)
            elif n.get('elsebody'):
                end=self.emit('JMP',0); j[-1]=len(self.code)+1
                self.stat(n['elsebody']); j=end
            j[-1]=len(self.code)+1
        else: reject(n)


HANDLERS = dict(K='R[a]=P[1][b]', NIL='R[a]=nil', MOVE='R[a]=R[b]', GLOBAL='R[a]=G[P[1][b]]', BOX='L[a]={R[b]}', READ='R[a]=(if b==0 then L else U)[c][1]', WRITE='(if a==0 then L else U)[b][1]=R[c]', TABLE='R[a]={}', GET='R[a]=R[b][R[c]]', SET='R[a][R[b]]=R[c]', JMP='pc=a', JF='if not R[a] then pc=b end', JT='if R[a] then pc=b end', CLOSURE='local v={} for j,h in ipairs(F[b][2]) do v[j]=(if h[1]==0 then L else U)[h[2]] end R[a]=function(...) return run(b,v,...) end', CALL='local p=args(R,I,5) local q=table.pack(R[b](table.unpack(p,1,p.n))) R[a]=if c==1 then q else q[1]', RETURN='local p=args(R,I,2) return table.unpack(p,1,p.n)')
HANDLERS.update({op:'R[a]=R[b] '+symbol+' R[c]' for op,symbol in BINARY.items()})
HANDLERS.update({op:'R[a]='+symbol+'R[b]' for op,symbol in UNARY.items()})


def literal(v):
    if isinstance(v,str): return '"'+''.join('\\%03d'%b for b in v.encode())+'"'
    if isinstance(v,bool): return str(v).lower()
    return repr(v)


def table(xs): return '{'+','.join(xs)+'}'


def varint(n):
    out=[]
    while n>=128: out.append(n%128+128); n//=128
    return bytes(out+[n])


# Fuse common instruction pairs, only inside a basic block. Rebase absolute
# branch destinations after compaction; never consume an instruction with an
# incoming edge. Comparison results are fresh temporaries from the compiler.
def fuse(code):
    targets={row[-1] for row in code if row[0] in ('JF','JT','JMP')}
    remap={}; out=[]; i=0
    while i<len(code):
        row=code[i]; remap[i+1]=len(out)+1
        nxt=code[i+1] if i+1<len(code) and i+2 not in targets else []
        if nxt and row[0].startswith('Compare') and nxt[0]=='JF' and nxt[1]==row[1]:
            # Preserve the result: the jump can be part of short-circuit logic.
            out.append(['BR_'+row[0],*row[1:],nxt[2]]); i+=2
        elif nxt and row[0]=='K' and nxt[0]=='BOX' and nxt[2]==row[1]:
            out.append(['KBOX',nxt[1],row[2]]); i+=2
        else:
            out.append(row.copy()); i+=1
    for row in out:
        if row[0] in ('JF','JT','JMP') or row[0].startswith('BR_'):
            row[-1]=remap[row[-1]]
    return out

HANDLERS['KBOX']='L[a]={P[1][b]}'
for op,symbol in BINARY.items():
    if op.startswith('Compare'):
        HANDLERS['BR_'+op]=HANDLERS[op]+' if not R[a] then pc=I[5] end'


def render(unit, seed):
    rng=random.Random(seed) if seed is not None else random.SystemRandom()
    used=sorted({row[0] for f in unit for row in f.code}); rng.shuffle(used)
    tags=dict(zip(used,rng.sample(range(1,max(127,len(used)*2)),len(used))))
    fs=[]
    for f in unit:
        blob=b''.join(varint(x) for op,*args in f.code for x in [len(args)+1,tags[op],*args])
        fs.append(table([table(map(literal,f.constants)),table(table(map(str,h)) for h in f.captures),'decode("'+blob.hex()+'")']))
    template=Path(__file__).with_name('runtime.luau.in').read_text()
    handlers=HANDLERS.copy()
    for op in used:
        if op.startswith('METHOD:'):
            handlers[op]=HANDLERS['CALL'].replace('R[b](', 'R[b]:'+op[7:]+'(')
    dispatch='\n'.join(('if' if i==0 else 'elseif')+f' op=={tags[op]} then '+handlers[op] for i,op in enumerate(used))+'\nelse error("invalid opcode") end'
    return template.replace('@FUNCTIONS@',table(fs)).replace('@DISPATCH@',dispatch)


def compile_file(path, parser, seed=None):
    proc=subprocess.run([parser,str(path.resolve())],capture_output=True)
    if proc.returncode: raise Unsupported(proc.stderr.decode(errors='replace').strip() or 'parser failed')
    ast=json.loads(proc.stdout); unit=[]; root=Function(unit)
    root.stat(ast['root']); root.emit('RETURN',0,0)
    for f in unit: f.code=fuse(f.code)
    return ' '.join(line.strip() for line in render(unit,seed).splitlines() if line.strip())


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__); cli.add_argument('source',type=Path); cli.add_argument('-o','--output',type=Path,required=True); cli.add_argument('--seed',type=int); cli.add_argument('--parser',default=os.getenv('LUAU_AST','luau-ast')); opt=cli.parse_args()
    try:
        if opt.source.resolve()==opt.output.resolve(): raise ValueError('choose an output different from the source')
        result=compile_file(opt.source,opt.parser,opt.seed); opt.output.write_text(result,encoding='utf-8')
    except (ValueError,OSError) as exc: sys.exit(f'loom: {exc}')

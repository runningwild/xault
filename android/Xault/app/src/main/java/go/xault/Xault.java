// Java Package xault is a proxy for talking to a Go program.
//   gobind -lang=java github.com/runningwild/xault/shared/phone/xault
//
// File is generated by gobind. Do not edit.
package go.xault;

import go.Seq;

public abstract class Xault {
    private Xault() {} // uninstantiable
    
    public static String Hello(String name) {
        go.Seq _in = new go.Seq();
        go.Seq _out = new go.Seq();
        String _result;
        _in.writeUTF16(name);
        Seq.send(DESCRIPTOR, CALL_Hello, _in, _out);
        _result = _out.readUTF16();
        return _result;
    }
    
    public static final class LifetimeState implements go.Seq.Object {
        private static final String DESCRIPTOR = "go.xault.LifetimeState";
        private static final int CALL_Load = 0x00c;
        private static final int CALL_MakeKeys = 0x10c;
        private static final int CALL_Store = 0x20c;
        private static final int CALL_Test = 0x30c;
        
        private go.Seq.Ref ref;
        
        private LifetimeState(go.Seq.Ref ref) { this.ref = ref; }
        
        public go.Seq.Ref ref() { return ref; }
        
        public void call(int code, go.Seq in, go.Seq out) {
            throw new RuntimeException("internal error: cycle: cannot call concrete proxy");
        }
        
        
        public void Load(byte[] data) throws Exception {
            go.Seq _in = new go.Seq();
            go.Seq _out = new go.Seq();
            _in.writeRef(ref);
            _in.writeByteArray(data);
            Seq.send(DESCRIPTOR, CALL_Load, _in, _out);
            String _err = _out.readUTF16();
            if (_err != null) {
                throw new Exception(_err);
            }
        }
        
        public void MakeKeys(PublicInfo info, long bits) throws Exception {
            go.Seq _in = new go.Seq();
            go.Seq _out = new go.Seq();
            _in.writeRef(ref);
            _in.writeRef(info.ref());
            _in.writeInt(bits);
            Seq.send(DESCRIPTOR, CALL_MakeKeys, _in, _out);
            String _err = _out.readUTF16();
            if (_err != null) {
                throw new Exception(_err);
            }
        }
        
        public byte[] Store() throws Exception {
            go.Seq _in = new go.Seq();
            go.Seq _out = new go.Seq();
            byte[] _result;
            _in.writeRef(ref);
            Seq.send(DESCRIPTOR, CALL_Store, _in, _out);
            _result = _out.readByteArray();
            String _err = _out.readUTF16();
            if (_err != null) {
                throw new Exception(_err);
            }
            return _result;
        }
        
        public String Test(String msg) throws Exception {
            go.Seq _in = new go.Seq();
            go.Seq _out = new go.Seq();
            String _result;
            _in.writeRef(ref);
            _in.writeUTF16(msg);
            Seq.send(DESCRIPTOR, CALL_Test, _in, _out);
            _result = _out.readUTF16();
            String _err = _out.readUTF16();
            if (_err != null) {
                throw new Exception(_err);
            }
            return _result;
        }
        
        @Override public boolean equals(Object o) {
            if (o == null || !(o instanceof LifetimeState)) {
                return false;
            }
            LifetimeState that = (LifetimeState)o;
            return true;
        }
        
        @Override public int hashCode() {
            return java.util.Arrays.hashCode(new Object[] {});
        }
        
        @Override public String toString() {
            StringBuilder b = new StringBuilder();
            b.append("LifetimeState").append("{");
            return b.append("}").toString();
        }
        
    }
    
    public static final class PublicInfo implements go.Seq.Object {
        private static final String DESCRIPTOR = "go.xault.PublicInfo";
        
        private go.Seq.Ref ref;
        
        private PublicInfo(go.Seq.Ref ref) { this.ref = ref; }
        
        public go.Seq.Ref ref() { return ref; }
        
        public void call(int code, go.Seq in, go.Seq out) {
            throw new RuntimeException("internal error: cycle: cannot call concrete proxy");
        }
        
        
        @Override public boolean equals(Object o) {
            if (o == null || !(o instanceof PublicInfo)) {
                return false;
            }
            PublicInfo that = (PublicInfo)o;
            return true;
        }
        
        @Override public int hashCode() {
            return java.util.Arrays.hashCode(new Object[] {});
        }
        
        @Override public String toString() {
            StringBuilder b = new StringBuilder();
            b.append("PublicInfo").append("{");
            return b.append("}").toString();
        }
        
    }
    
    public static String Test2(String msg) throws Exception {
        go.Seq _in = new go.Seq();
        go.Seq _out = new go.Seq();
        String _result;
        _in.writeUTF16(msg);
        Seq.send(DESCRIPTOR, CALL_Test2, _in, _out);
        _result = _out.readUTF16();
        String _err = _out.readUTF16();
        if (_err != null) {
            throw new Exception(_err);
        }
        return _result;
    }
    
    private static final int CALL_Hello = 1;
    private static final int CALL_Test2 = 2;
    private static final String DESCRIPTOR = "xault";
}

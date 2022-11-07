package xexloaderwv;

import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.data.DataType;

public class TypeRecord {

	public enum LeafRecordKind
    {
        LF_VTSHAPE 			("LF_VTSHAPE", 0x000a),
        LF_LABEL 			("LF_LABEL",0x000e),
        LF_ENDPRECOMP 		("LF_ENDPRECOMP",0x0014),
        LF_MODIFIER 		("LF_MODIFIER",0x1001),
        LF_POINTER 			("LF_POINTER", 0x1002),
        LF_PROCEDURE 		("LF_PROCEDURE", 0x1008),
        LF_MFUNCTION 		("LF_MFUNCTION", 0x1009),
        LF_ARGLIST 			("LF_ARGLIST", 0x1201),
        LF_FIELDLIST 		("LF_FIELDLIST", 0x1203),
        LF_BITFIELD 		("LF_BITFIELD", 0x1205),
        LF_METHODLIST 		("LF_METHODLIST", 0x1206),
        LF_ARRAY 			("LF_ARRAY",0x1503),
        LF_CLASS 			("LF_CLASS", 0x1504),
        LF_STRUCTURE 		("LF_STRUCTURE", 0x1505),
        LF_UNION			("LF_UNION",0x1506),
        LF_ENUM 			("LF_ENUM", 0x1507),
        LF_PRECOMP 			("LF_PRECOMP", 0x1509),
        LF_TYPESERVER2 		("LF_TYPESERVER2",0x1515),
        LF_INTERFACE 		("LF_INTERFACE",0x1519),
        LF_VFTABLE 			("LF_VFTABLE", 0x151d),
        LF_FUNC_ID 			("LF_FUNC_ID", 0x1601),
        LF_MFUNC_ID 		("LF_MFUNC_ID", 0x1602),
        LF_BUILDINFO 		("LF_BUILDINFO",0x1603),
        LF_SUBSTR_LIST 		("LF_SUBSTR_LIST", 0x1604),
        LF_STRING_ID 		("LF_STRING_ID",0x1605),
        LF_UDT_SRC_LINE 	("LF_UDT_SRC_LINE",0x1606),
        LF_UDT_MOD_SRC_LINE ("LF_UDT_SRC_LINE",0x1607);
		private final String name;
        private final long value;
        private LeafRecordKind(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static LeafRecordKind getByValue(long l)
        {
        	for(LeafRecordKind lr : LeafRecordKind.values())
        		if(lr.value == l)
        			return lr;
        	return null;
        }
    }
	
	public enum MemberRecordKind
    {
		LF_BCLASS 		("LF_BCLASS" , 0x1400),
		LF_VBCLASS 		("LF_VBCLASS" , 0x1401),
		LF_IVBCLASS 	("LF_IVBCLASS" , 0x1402),
		LF_INDEX 		("LF_INDEX" , 0x1404),
		LF_VFUNCTAB 	("LF_VFUNCTAB" , 0x1409),
		LF_ENUMERATE 	("LF_ENUMERATE" , 0x1502),
		LF_MEMBER 		("LF_MEMBER" , 0x150d),
		LF_STMEMBER 	("LF_STMEMBER" , 0x150e),
		LF_METHOD 		("LF_METHOD" , 0x150f),
		LF_NESTTYPE 	("LF_NESTTYPE" , 0x1510),
		LF_ONEMETHOD 	("LF_ONEMETHOD" , 0x1511),
		LF_BINTERFACE 	("LF_BINTERFACE" , 0x151a),;
		private final String name;
        private final long value;
        private MemberRecordKind(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static MemberRecordKind getByValue(long l)
        {
        	for(MemberRecordKind mr : MemberRecordKind.values())
        		if(mr.value == l)
        			return mr;
        	return null;
        }
    }
	
	public enum ValueType
    {
		LF_CHAR 		("LF_CHAR", 0x8000),
		LF_SHORT 		("LF_SHORT", 0x8001),
		LF_USHORT 		("LF_USHORT", 0x8002),
		LF_LONG 		("LF_LONG", 0x8003),
		LF_ULONG 		("LF_ULONG", 0x8004),
		LF_REAL32 		("LF_REAL32", 0x8005),
		LF_REAL64 		("LF_REAL64", 0x8006),
		LF_REAL80 		("LF_REAL80", 0x8007),
		LF_REAL128 		("LF_REAL128", 0x8008),
		LF_QUADWORD 	("LF_QUADWORD", 0x8009),
		LF_UQUADWORD 	("LF_UQUADWORD", 0x800a),
		LF_REAL48 		("LF_REAL48", 0x800b),
		LF_COMPLEX32 	("LF_COMPLEX32", 0x800c),
		LF_COMPLEX64 	("LF_COMPLEX64", 0x800d),
		LF_COMPLEX80 	("LF_COMPLEX80", 0x800e),
		LF_COMPLEX128 	("LF_COMPLEX128", 0x800f),
		LF_VARSTRING 	("LF_VARSTRING", 0x8010),
		LF_OCTWORD 		("LF_OCTWORD", 0x8017),
		LF_UOCTWORD 	("LF_UOCTWORD", 0x8018),
		LF_DECIMAL 		("LF_DECIMAL", 0x8019),
		LF_DATE 		("LF_DATE", 0x801a),
		LF_UTF8STRING 	("LF_UTF8STRING", 0x801b),
		LF_REAL16 		("LF_REAL16", 0x801c);
		private final String name;
        private final long value;
        private ValueType(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static ValueType getByValue(long l)
        {
        	for(ValueType t : ValueType.values())
        		if(t.value == l)
        			return t;
        	return null;
        }
    }
	
	public enum MProp
    {
		MTvanilla   ("MTvanilla", 0x00),
		MTvirtual   ("MTvirtual", 0x01),
		MTstatic    ("MTstatic", 0x02),
		MTfriend    ("MTfriend", 0x03),
		MTintro     ("MTintro", 0x04),
		MTpurevirt  ("MTpurevirt", 0x05),
		MTpureintro ("MTpureintro", 0x06),
		error       ("error", 0x07);
		private final String name;
        private final long value;
        private MProp(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static MProp getByValue(long l)
        {
        	for(MProp mp : MProp.values())
        		if(mp.value == l)
        			return mp;
        	return null;
        }
    }
	
	public enum Access
    {
		_unknown 	("_unknown", 0),
		_private 	("_private", 1),
		_protected 	("_protected", 2),
		_public 	("_public", 3);
		private final String name;
        private final long value;
        private Access(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static Access getByValue(long l)
        {
        	for(Access a : Access.values())
        		if(a.value == l)
        			return a;
        	return null;
        }
    }
	
	public enum PointerType
    {
		PTR_BASE_SEG 		("PTR_BASE_SEG", 0x03),
		PTR_BASE_VAL 		("PTR_BASE_VAL", 0x04),
		PTR_BASE_SEGVAL 	("PTR_BASE_SEGVAL", 0x05),
		PTR_BASE_ADDR 		("PTR_BASE_ADDR", 0x06),
		PTR_BASE_SEGADDR 	("PTR_BASE_SEGADDR", 0x07),
		PTR_BASE_TYPE 		("PTR_BASE_TYPE", 0x08),
		PTR_BASE_SELF 		("PTR_BASE_SELF", 0x09),
		PTR_NEAR32 			("PTR_NEAR32", 0x0a),
		PTR_64 				("PTR_64", 0x0c),
		PTR_UNUSEDPTR 		("PTR_UNUSEDPTR", 0x0d);
		private final String name;
        private final long value;
        private PointerType(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static PointerType getByValue(long l)
        {
        	for(PointerType p : PointerType.values())
        		if(p.value == l)
        			return p;
        	return null;
        }
    }
	
	public enum PointerMode
    {
		PTR_MODE_PTR 		("PTR_MODE_PTR", 0x00),
		PTR_MODE_REF 		("PTR_MODE_REF", 0x01),
		PTR_MODE_PMEM 		("PTR_MODE_PMEM", 0x02),
		PTR_MODE_PMFUNC 	("PTR_MODE_PMFUNC", 0x03),
		PTR_MODE_RESERVED 	("PTR_MODE_RESERVED", 0x04);
		private final String name;
        private final long value;
        private PointerMode(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static PointerMode getByValue(long l)
        {
        	for(PointerMode p : PointerMode.values())
        		if(p.value == l)
        			return p;
        	return null;
        }
    }
	
	public enum BasicTypes
    {
		T_NOTYPE        ("T_NOTYPE", 0x0000),
		T_ABS           ("T_ABS", 0x0001),
		T_SEGMENT       ("T_SEGMENT", 0x0002),
		T_VOID          ("T_VOID", 0x0003),
		T_HRESULT       ("T_HRESULT", 0x0008),
		T_32PHRESULT    ("T_32PHRESULT", 0x0408),
		T_64PHRESULT    ("T_64PHRESULT", 0x0608),
		T_PVOID         ("T_PVOID", 0x0103),
		T_PFVOID        ("T_PFVOID", 0x0203),
		T_PHVOID        ("T_PHVOID", 0x0303),
		T_32PVOID       ("T_32PVOID", 0x0403),
		T_32PFVOID      ("T_32PFVOID", 0x0503),
		T_64PVOID       ("T_64PVOID", 0x0603),
		T_CURRENCY      ("T_CURRENCY", 0x0004),
		T_NBASICSTR     ("T_NBASICSTR", 0x0005),
		T_FBASICSTR     ("T_FBASICSTR", 0x0006),
		T_NOTTRANS      ("T_NOTTRANS", 0x0007),
		T_BIT           ("T_BIT", 0x0060),
		T_PASCHAR       ("T_PASCHAR", 0x0061),
		T_BOOL32FF      ("T_BOOL32FF", 0x0062),
		T_CHAR          ("T_CHAR", 0x0010),
		T_PCHAR         ("T_PCHAR", 0x0110),
		T_PFCHAR        ("T_PFCHAR", 0x0210),
		T_PHCHAR        ("T_PHCHAR", 0x0310),
		T_32PCHAR       ("T_32PCHAR", 0x0410),
		T_32PFCHAR      ("T_32PFCHAR", 0x0510),
		T_64PCHAR       ("T_64PCHAR", 0x0610),
		T_UCHAR         ("T_UCHAR", 0x0020),
		T_PUCHAR        ("T_PUCHAR", 0x0120),
		T_PFUCHAR       ("T_PFUCHAR", 0x0220),
		T_PHUCHAR       ("T_PHUCHAR", 0x0320),
		T_32PUCHAR      ("T_32PUCHAR", 0x0420),
		T_32PFUCHAR     ("T_32PFUCHAR", 0x0520),
		T_64PUCHAR      ("T_64PUCHAR", 0x0620),
		T_RCHAR         ("T_RCHAR", 0x0070),
		T_PRCHAR        ("T_PRCHAR", 0x0170),
		T_PFRCHAR       ("T_PFRCHAR", 0x0270),
		T_PHRCHAR       ("T_PHRCHAR", 0x0370),
		T_32PRCHAR      ("T_32PRCHAR", 0x0470),
		T_32PFRCHAR     ("T_32PFRCHAR", 0x0570),
		T_64PRCHAR      ("T_64PRCHAR", 0x0670),
		T_WCHAR         ("T_WCHAR", 0x0071),
		T_PWCHAR        ("T_PWCHAR", 0x0171),
		T_PFWCHAR       ("T_PFWCHAR", 0x0271),
		T_PHWCHAR       ("T_PHWCHAR", 0x0371),
		T_32PWCHAR      ("T_32PWCHAR", 0x0471),
		T_32PFWCHAR     ("T_32PFWCHAR", 0x0571),
		T_64PWCHAR      ("T_64PWCHAR", 0x0671),
		T_CHAR16        ("T_CHAR16", 0x007a),
		T_PCHAR16       ("T_PCHAR16", 0x017a),
		T_PFCHAR16      ("T_PFCHAR16", 0x027a),
		T_PHCHAR16      ("T_PHCHAR16", 0x037a),
		T_32PCHAR16     ("T_32PCHAR16", 0x047a),
		T_32PFCHAR16    ("T_32PFCHAR16", 0x057a),
		T_64PCHAR16     ("T_64PCHAR16", 0x067a),
		T_CHAR32        ("T_CHAR32", 0x007b),
		T_PCHAR32       ("T_PCHAR32", 0x017b),
		T_PFCHAR32      ("T_PFCHAR32", 0x027b),
		T_PHCHAR32      ("T_PHCHAR32", 0x037b),
		T_32PCHAR32     ("T_32PCHAR32", 0x047b),
		T_32PFCHAR32    ("T_32PFCHAR32", 0x057b),
		T_64PCHAR32     ("T_64PCHAR32", 0x067b),
		T_INT1          ("T_INT1", 0x0068),
		T_PINT1         ("T_PINT1", 0x0168),
		T_PFINT1        ("T_PFINT1", 0x0268),
		T_PHINT1        ("T_PHINT1", 0x0368),
		T_32PINT1       ("T_32PINT1", 0x0468),
		T_32PFINT1      ("T_32PFINT1", 0x0568),
		T_64PINT1       ("T_64PINT1", 0x0668),
		T_UINT1         ("T_UINT1", 0x0069),
		T_PUINT1        ("T_PUINT1", 0x0169),
		T_PFUINT1       ("T_PFUINT1", 0x0269),
		T_PHUINT1       ("T_PHUINT1", 0x0369),
		T_32PUINT1      ("T_32PUINT1", 0x0469),
		T_32PFUINT1     ("T_32PFUINT1", 0x0569),
		T_64PUINT1      ("T_64PUINT1", 0x0669),
		T_SHORT         ("T_SHORT", 0x0011),
		T_PSHORT        ("T_PSHORT", 0x0111),
		T_PFSHORT       ("T_PFSHORT", 0x0211),
		T_PHSHORT       ("T_PHSHORT", 0x0311),
		T_32PSHORT      ("T_32PSHORT", 0x0411),
		T_32PFSHORT     ("T_32PFSHORT", 0x0511),
		T_64PSHORT      ("T_64PSHORT", 0x0611),
		T_USHORT        ("T_USHORT", 0x0021),
		T_PUSHORT       ("T_PUSHORT", 0x0121),
		T_PFUSHORT      ("T_PFUSHORT", 0x0221),
		T_PHUSHORT      ("T_PHUSHORT", 0x0321),
		T_32PUSHORT     ("T_32PUSHORT", 0x0421),
		T_32PFUSHORT    ("T_32PFUSHORT", 0x0521),
		T_64PUSHORT     ("T_64PUSHORT", 0x0621),
		T_INT2          ("T_INT2", 0x0072),
		T_PINT2         ("T_PINT2", 0x0172),
		T_PFINT2        ("T_PFINT2", 0x0272),
		T_PHINT2        ("T_PHINT2", 0x0372),
		T_32PINT2       ("T_32PINT2", 0x0472),
		T_32PFINT2      ("T_32PFINT2", 0x0572),
		T_64PINT2       ("T_64PINT2", 0x0672),
		T_UINT2         ("T_UINT2", 0x0073),
		T_PUINT2        ("T_PUINT2", 0x0173),
		T_PFUINT2       ("T_PFUINT2", 0x0273),
		T_PHUINT2       ("T_PHUINT2", 0x0373),
		T_32PUINT2      ("T_32PUINT2", 0x0473),
		T_32PFUINT2     ("T_32PFUINT2", 0x0573),
		T_64PUINT2      ("T_64PUINT2", 0x0673),
		T_LONG          ("T_LONG", 0x0012),
		T_ULONG         ("T_ULONG", 0x0022),
		T_PLONG         ("T_PLONG", 0x0112),
		T_PULONG        ("T_PULONG", 0x0122),
		T_PFLONG        ("T_PFLONG", 0x0212),
		T_PFULONG       ("T_PFULONG", 0x0222),
		T_PHLONG        ("T_PHLONG", 0x0312),
		T_PHULONG       ("T_PHULONG", 0x0322),
		T_32PLONG       ("T_32PLONG", 0x0412),
		T_32PULONG      ("T_32PULONG", 0x0422),
		T_32PFLONG      ("T_32PFLONG", 0x0512),
		T_32PFULONG     ("T_32PFULONG", 0x0522),
		T_64PLONG       ("T_64PLONG", 0x0612),
		T_64PULONG      ("T_64PULONG", 0x0622),
		T_INT4          ("T_INT4", 0x0074),
		T_PINT4         ("T_PINT4", 0x0174),
		T_PFINT4        ("T_PFINT4", 0x0274),
		T_PHINT4        ("T_PHINT4", 0x0374),
		T_32PINT4       ("T_32PINT4", 0x0474),
		T_32PFINT4      ("T_32PFINT4", 0x0574),
		T_64PINT4       ("T_64PINT4", 0x0674),
		T_UINT4         ("T_UINT4", 0x0075),
		T_PUINT4        ("T_PUINT4", 0x0175),
		T_PFUINT4       ("T_PFUINT4", 0x0275),
		T_PHUINT4       ("T_PHUINT4", 0x0375),
		T_32PUINT4      ("T_32PUINT4", 0x0475),
		T_32PFUINT4     ("T_32PFUINT4", 0x0575),
		T_64PUINT4      ("T_64PUINT4", 0x0675),
		T_QUAD          ("T_QUAD", 0x0013),
		T_PQUAD         ("T_PQUAD", 0x0113),
		T_PFQUAD        ("T_PFQUAD", 0x0213),
		T_PHQUAD        ("T_PHQUAD", 0x0313),
		T_32PQUAD       ("T_32PQUAD", 0x0413),
		T_32PFQUAD      ("T_32PFQUAD", 0x0513),
		T_64PQUAD       ("T_64PQUAD", 0x0613),
		T_UQUAD         ("T_UQUAD", 0x0023),
		T_PUQUAD        ("T_PUQUAD", 0x0123),
		T_PFUQUAD       ("T_PFUQUAD", 0x0223),
		T_PHUQUAD       ("T_PHUQUAD", 0x0323),
		T_32PUQUAD      ("T_32PUQUAD", 0x0423),
		T_32PFUQUAD     ("T_32PFUQUAD", 0x0523),
		T_64PUQUAD      ("T_64PUQUAD", 0x0623),
		T_INT8          ("T_INT8", 0x0076),
		T_PINT8         ("T_PINT8", 0x0176),
		T_PFINT8        ("T_PFINT8", 0x0276),
		T_PHINT8        ("T_PHINT8", 0x0376),
		T_32PINT8       ("T_32PINT8", 0x0476),
		T_32PFINT8      ("T_32PFINT8", 0x0576),
		T_64PINT8       ("T_64PINT8", 0x0676),
		T_UINT8         ("T_UINT8", 0x0077),
		T_PUINT8        ("T_PUINT8", 0x0177),
		T_PFUINT8       ("T_PFUINT8", 0x0277),
		T_PHUINT8       ("T_PHUINT8", 0x0377),
		T_32PUINT8      ("T_32PUINT8", 0x0477),
		T_32PFUINT8     ("T_32PFUINT8", 0x0577),
		T_64PUINT8      ("T_64PUINT8", 0x0677),
		T_OCT           ("T_OCT", 0x0014),
		T_POCT          ("T_POCT", 0x0114),
		T_PFOCT         ("T_PFOCT", 0x0214),
		T_PHOCT         ("T_PHOCT", 0x0314),
		T_32POCT        ("T_32POCT", 0x0414),
		T_32PFOCT       ("T_32PFOCT", 0x0514),
		T_64POCT        ("T_64POCT", 0x0614),
		T_UOCT          ("T_UOCT", 0x0024),
		T_PUOCT         ("T_PUOCT", 0x0124),
		T_PFUOCT        ("T_PFUOCT", 0x0224),
		T_PHUOCT        ("T_PHUOCT", 0x0324),
		T_32PUOCT       ("T_32PUOCT", 0x0424),
		T_32PFUOCT      ("T_32PFUOCT", 0x0524),
		T_64PUOCT       ("T_64PUOCT", 0x0624),
		T_INT16         ("T_INT16", 0x0078),
		T_PINT16        ("T_PINT16", 0x0178),
		T_PFINT16       ("T_PFINT16", 0x0278),
		T_PHINT16       ("T_PHINT16", 0x0378),
		T_32PINT16      ("T_32PINT16", 0x0478),
		T_32PFINT16     ("T_32PFINT16", 0x0578),
		T_64PINT16      ("T_64PINT16", 0x0678),
		T_UINT16        ("T_UINT16", 0x0079),
		T_PUINT16       ("T_PUINT16", 0x0179),
		T_PFUINT16      ("T_PFUINT16", 0x0279),
		T_PHUINT16      ("T_PHUINT16", 0x0379),
		T_32PUINT16     ("T_32PUINT16", 0x0479),
		T_32PFUINT16    ("T_32PFUINT16", 0x0579),
		T_64PUINT16     ("T_64PUINT16", 0x0679),
		T_REAL16        ("T_REAL16", 0x0046),
		T_PREAL16       ("T_PREAL16", 0x0146),
		T_PFREAL16      ("T_PFREAL16", 0x0246),
		T_PHREAL16      ("T_PHREAL16", 0x0346),
		T_32PREAL16     ("T_32PREAL16", 0x0446),
		T_32PFREAL16    ("T_32PFREAL16", 0x0546),
		T_64PREAL16     ("T_64PREAL16", 0x0646),
		T_REAL32        ("T_REAL32", 0x0040),
		T_PREAL32       ("T_PREAL32", 0x0140),
		T_PFREAL32      ("T_PFREAL32", 0x0240),
		T_PHREAL32      ("T_PHREAL32", 0x0340),
		T_32PREAL32     ("T_32PREAL32", 0x0440),
		T_32PFREAL32    ("T_32PFREAL32", 0x0540),
		T_64PREAL32     ("T_64PREAL32", 0x0640),
		T_REAL32PP      ("T_REAL32PP", 0x0045),
		T_PREAL32PP     ("T_PREAL32PP", 0x0145),
		T_PFREAL32PP    ("T_PFREAL32PP", 0x0245),
		T_PHREAL32PP    ("T_PHREAL32PP", 0x0345),
		T_32PREAL32PP   ("T_32PREAL32PP", 0x0445),
		T_32PFREAL32PP  ("T_32PFREAL32PP", 0x0545),
		T_64PREAL32PP   ("T_64PREAL32PP", 0x0645),
		T_REAL48        ("T_REAL48", 0x0044),
		T_PREAL48       ("T_PREAL48", 0x0144),
		T_PFREAL48      ("T_PFREAL48", 0x0244),
		T_PHREAL48      ("T_PHREAL48", 0x0344),
		T_32PREAL48     ("T_32PREAL48", 0x0444),
		T_32PFREAL48    ("T_32PFREAL48", 0x0544),
		T_64PREAL48     ("T_64PREAL48", 0x0644),
		T_REAL64        ("T_REAL64", 0x0041),
		T_PREAL64       ("T_PREAL64", 0x0141),
		T_PFREAL64      ("T_PFREAL64", 0x0241),
		T_PHREAL64      ("T_PHREAL64", 0x0341),
		T_32PREAL64     ("T_32PREAL64", 0x0441),
		T_32PFREAL64    ("T_32PFREAL64", 0x0541),
		T_64PREAL64     ("T_64PREAL64", 0x0641),
		T_REAL80        ("T_REAL80", 0x0042),
		T_PREAL80       ("T_PREAL80", 0x0142),
		T_PFREAL80      ("T_PFREAL80", 0x0242),
		T_PHREAL80      ("T_PHREAL80", 0x0342),
		T_32PREAL80     ("T_32PREAL80", 0x0442),
		T_32PFREAL80    ("T_32PFREAL80", 0x0542),
		T_64PREAL80     ("T_64PREAL80", 0x0642),
		T_REAL128       ("T_REAL128", 0x0043),
		T_PREAL128      ("T_PREAL128", 0x0143),
		T_PFREAL128     ("T_PFREAL128", 0x0243),
		T_PHREAL128     ("T_PHREAL128", 0x0343),
		T_32PREAL128    ("T_32PREAL128", 0x0443),
		T_32PFREAL128   ("T_32PFREAL128", 0x0543),
		T_64PREAL128    ("T_64PREAL128", 0x0643),
		T_CPLX32        ("T_CPLX32", 0x0050),
		T_PCPLX32       ("T_PCPLX32", 0x0150),
		T_PFCPLX32      ("T_PFCPLX32", 0x0250),
		T_PHCPLX32      ("T_PHCPLX32", 0x0350),
		T_32PCPLX32     ("T_32PCPLX32", 0x0450),
		T_32PFCPLX32    ("T_32PFCPLX32", 0x0550),
		T_64PCPLX32     ("T_64PCPLX32", 0x0650),
		T_CPLX64        ("T_CPLX64", 0x0051),
		T_PCPLX64       ("T_PCPLX64", 0x0151),
		T_PFCPLX64      ("T_PFCPLX64", 0x0251),
		T_PHCPLX64      ("T_PHCPLX64", 0x0351),
		T_32PCPLX64     ("T_32PCPLX64", 0x0451),
		T_32PFCPLX64    ("T_32PFCPLX64", 0x0551),
		T_64PCPLX64     ("T_64PCPLX64", 0x0651),
		T_CPLX80        ("T_CPLX80", 0x0052),
		T_PCPLX80       ("T_PCPLX80", 0x0152),
		T_PFCPLX80      ("T_PFCPLX80", 0x0252),
		T_PHCPLX80      ("T_PHCPLX80", 0x0352),
		T_32PCPLX80     ("T_32PCPLX80", 0x0452),
		T_32PFCPLX80    ("T_32PFCPLX80", 0x0552),
		T_64PCPLX80     ("T_64PCPLX80", 0x0652),
		T_CPLX128       ("T_CPLX128", 0x0053),
		T_PCPLX128      ("T_PCPLX128", 0x0153),
		T_PFCPLX128     ("T_PFCPLX128", 0x0253),
		T_PHCPLX128     ("T_PHCPLX128", 0x0353),
		T_32PCPLX128    ("T_32PCPLX128", 0x0453),
		T_32PFCPLX128   ("T_32PFCPLX128", 0x0553),
		T_64PCPLX128    ("T_64PCPLX128", 0x0653),
		T_BOOL08        ("T_BOOL08", 0x0030),
		T_PBOOL08       ("T_PBOOL08", 0x0130),
		T_PFBOOL08      ("T_PFBOOL08", 0x0230),
		T_PHBOOL08      ("T_PHBOOL08", 0x0330),
		T_32PBOOL08     ("T_32PBOOL08", 0x0430),
		T_32PFBOOL08    ("T_32PFBOOL08", 0x0530),
		T_64PBOOL08     ("T_64PBOOL08", 0x0630),
		T_BOOL16        ("T_BOOL16", 0x0031),
		T_PBOOL16       ("T_PBOOL16", 0x0131),
		T_PFBOOL16      ("T_PFBOOL16", 0x0231),
		T_PHBOOL16      ("T_PHBOOL16", 0x0331),
		T_32PBOOL16     ("T_32PBOOL16", 0x0431),
		T_32PFBOOL16    ("T_32PFBOOL16", 0x0531),
		T_64PBOOL16     ("T_64PBOOL16", 0x0631),
		T_BOOL32        ("T_BOOL32", 0x0032),
		T_PBOOL32       ("T_PBOOL32", 0x0132),
		T_PFBOOL32      ("T_PFBOOL32", 0x0232),
		T_PHBOOL32      ("T_PHBOOL32", 0x0332),
		T_32PBOOL32     ("T_32PBOOL32", 0x0432),
		T_32PFBOOL32    ("T_32PFBOOL32", 0x0532),
		T_64PBOOL32     ("T_64PBOOL32", 0x0632),
		T_BOOL64        ("T_BOOL64", 0x0033),
		T_PBOOL64       ("T_PBOOL64", 0x0133),
		T_PFBOOL64      ("T_PFBOOL64", 0x0233),
		T_PHBOOL64      ("T_PHBOOL64", 0x0333),
		T_32PBOOL64     ("T_32PBOOL64", 0x0433),
		T_32PFBOOL64    ("T_32PFBOOL64", 0x0533),
		T_64PBOOL64     ("T_64PBOOL64", 0x0633),
		T_NCVPTR        ("T_NCVPTR", 0x01f0),
		T_FCVPTR        ("T_FCVPTR", 0x02f0),
		T_HCVPTR        ("T_HCVPTR", 0x03f0),
		T_32NCVPTR      ("T_32NCVPTR", 0x04f0),
		T_32FCVPTR      ("T_32FCVPTR", 0x05f0),
		T_64NCVPTR      ("T_64NCVPTR", 0x06f0);
		private final String name;
        private final long value;
        private BasicTypes(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static BasicTypes getByValue(long l)
        {
        	for(BasicTypes bt : BasicTypes.values())
        		if(bt.value == l)
        			return bt;
        	return null;
        }
    }
	
	public enum CallType
    {
		NEAR_C 			("NEAR_C", 0x00000000),
		FAR_C 			("FAR_C", 0x00000001),
		NEAR_PASCAL 	("NEAR_PASCAL", 0x00000002),
		FAR_PASCAL 		("FAR_PASCAL", 0x00000003),
		NEAR_FAST 		("NEAR_FAST", 0x00000004),
		FAR_FAST 		("FAR_FAST", 0x00000005),
		SKIPPED 		("SKIPPED", 0x00000006),
		NEAR_STD 		("NEAR_STD", 0x00000007),
		FAR_STD 		("FAR_STD", 0x00000008),
		NEAR_SYS 		("NEAR_SYS", 0x00000009),
		FAR_SYS 		("FAR_SYS", 0x0000000A),
		THISCALL 		("THISCALL", 0x0000000B),
		MIPSCALL 		("MIPSCALL", 0x0000000C),
		GENERIC 		("GENERIC", 0x0000000D),
		ALPHACALL 		("ALPHACALL", 0x0000000E),
		PPCCALL 		("PPCCALL", 0x0000000F),
		SHCALL 			("SHCALL", 0x00000010),
		ARMCALL 		("ARMCALL", 0x00000011),
		AM33CALL 		("AM33CALL", 0x00000012),
		TRICALL 		("TRICALL", 0x00000013),
		SH5CALL 		("SH5CALL", 0x00000014),
		M32RCALL 		("M32RCALL", 0x00000015),
		RESERVED 		("RESERVED", 0x00000016);
		private final String name;
        private final long value;
        private CallType(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static CallType getByValue(long l)
        {
        	for(CallType ct : CallType.values())
        		if(ct.value == l)
        			return ct;
        	return null;
        }
    }
	
	public enum ModAttr
    {
		MOD_const  		("MOD_const", 0x00000001),
		MOD_volatile 	("MOD_volatile", 0x00000002),
		MOD_unaligned	("MOD_unaligned", 0x00000004);
		private final String name;
        private final long value;
        private ModAttr(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static ModAttr getByValue(long l)
        {
        	for(ModAttr m : ModAttr.values())
        		if(m.value == l)
        			return m;
        	return null;
        }
    }
	
	public enum Shape
    {
		near 	("near", 0x00),
		far 	("far", 0x01),
		thin 	("thin", 0x02),
		outer 	("outer", 0x03),
		meta 	("meta", 0x04),
		near32 	("near32", 0x05),
		far32 	("far32", 0x06),
		unused 	("unused", 0x07);
		private final String name;
        private final long value;
        private Shape(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static Shape getByValue(long l)
        {
        	for(Shape s : Shape.values())
        		if(s.value == l)
        			return s;
        	return null;
        }
    }	
	
	public enum MOCOM_UDT
    {
		CV_MOCOM_UDT_none		("CV_MOCOM_UDT_none", 0x00),
		CV_MOCOM_UDT_ref 		("CV_MOCOM_UDT_ref", 0x01),
		CV_MOCOM_UDT_value 		("CV_MOCOM_UDT_value", 0x02),
		CV_MOCOM_UDT_interface 	("CV_MOCOM_UDT_interface", 0x03);
		private final String name;
        private final long value;
        private MOCOM_UDT(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static MOCOM_UDT getByValue(long l)
        {
        	for(MOCOM_UDT u : MOCOM_UDT.values())
        		if(u.value == l)
        			return u;
        	return null;
        }
    }
	
	public abstract class LeafRecord
    { 
		public DataType dataType = null;
    }
	
	public abstract class MemberRecord
    {
		public MemberRecordKind recordKind;
		public abstract long GetSize();
    }
	
	public class FieldAttribute
	{
        public boolean noconstruct;
        public boolean noinherit;
        public boolean pseudo;
        public MProp mprop;
        public Access access;
        public boolean compgenx;
		public int _raw;
		public FieldAttribute(int attr)
		{
			_raw = attr;
			 access = Access.getByValue(Helper.GetBits(attr, 0, 2));
             mprop = MProp.getByValue(Helper.GetBits(attr, 2, 3));
             pseudo = Helper.GetBits(attr, 5, 1) != 0;
             noinherit = Helper.GetBits(attr, 6, 1) != 0;
             noconstruct = Helper.GetBits(attr, 7, 1) != 0;
             compgenx = Helper.GetBits(attr, 8, 1) != 0;
		}
	}
	
	public class Property
	{
        public boolean packed;
        public boolean ctor;
        public boolean ovlops;
        public boolean isnested;
        public boolean cnested;
        public boolean opassign;
        public boolean opcast;
        public boolean fwdref;
        public boolean scoped;
        public boolean hasuniquename;
        public boolean sealed;
        public boolean hfa;
        public boolean intrinsic;
        public MOCOM_UDT udt;
        public boolean reserved;
		public int _raw;
		public Property(int u)
		{
			_raw = u;
			packed = Helper.GetBits(u, 0, 1) != 0;
            ctor = Helper.GetBits(u, 1, 1) != 0;
            ovlops = Helper.GetBits(u, 2, 1) != 0;
            isnested = Helper.GetBits(u, 3, 1) != 0;
            cnested = Helper.GetBits(u, 4, 1) != 0;
            opassign = Helper.GetBits(u, 5, 1) != 0;
            opcast = Helper.GetBits(u, 6, 1) != 0;
            fwdref = Helper.GetBits(u, 7, 1) != 0;
            scoped = Helper.GetBits(u, 8, 1) != 0;
            hasuniquename = Helper.GetBits(u, 9, 1) != 0;
            sealed = Helper.GetBits(u, 10, 1) != 0;
            hfa = Helper.GetBits(u, 11, 1) != 0;
            intrinsic = Helper.GetBits(u, 12, 1) != 0;
            udt = MOCOM_UDT.getByValue(Helper.GetBits(u, 13, 2));
            reserved = Helper.GetBits(u, 15, 1) != 0;
		}
	}
	
	public class Value
	{
		public ValueType type;
		public byte[] data;
		public int _rawSize;		
		public long val_long;
		private BinaryReader dataReader;
		
		private void SetData(byte[] d)
		{			
			data = d;
			dataReader = new BinaryReader(new ByteArrayProvider(data), true);
			_rawSize += d.length;
		}
		
		public Value(BinaryReader b, long pos) throws Exception
		{
			int test = b.readUnsignedShort(pos);
			_rawSize = 2;
			if(test < 0x8000)
			{
				type = ValueType.LF_USHORT;
				data = b.readByteArray(pos, 2);
				dataReader = new BinaryReader(new ByteArrayProvider(data), true);
                val_long = dataReader.readUnsignedValue(0, 2);
			}
			else
			{
				type = ValueType.getByValue(test);
				switch(type)
				{
					 case LF_CHAR:
	                     SetData(b.readByteArray(pos + 2, 1));	    
	                     val_long = dataReader.readUnsignedValue(0, 1);
	                     break;
                     case LF_REAL16:
                     case LF_SHORT:
                     case LF_USHORT:
	                     SetData(b.readByteArray(pos + 2, 2));        
	                     val_long = dataReader.readUnsignedValue(0, 2);
                    	 break;
                     case LF_LONG:
                     case LF_ULONG:
                     case LF_REAL32:
	                     SetData(b.readByteArray(pos + 2, 4));      
	                     val_long = dataReader.readUnsignedValue(0, 4);
                    	 break;
                     case LF_REAL48:
	                     SetData(b.readByteArray(pos + 2, 6));
                    	 break;
                     case LF_DATE:
                     case LF_COMPLEX32:
                     case LF_REAL64:
                     case LF_QUADWORD:
                     case LF_UQUADWORD:
	                     SetData(b.readByteArray(pos + 2, 8));        
	                     val_long = dataReader.readUnsignedValue(0, 8);
                    	 break;
                     case LF_REAL80:
	                     SetData(b.readByteArray(pos + 2, 10));
                    	 break;    
                	 case LF_DECIMAL:
                     case LF_OCTWORD:
                     case LF_UOCTWORD:
                     case LF_COMPLEX64:
                     case LF_REAL128:
	                     SetData(b.readByteArray(pos + 2, 16));
                    	 break;
                     case LF_COMPLEX80:
	                     SetData(b.readByteArray(pos + 2, 20));
                    	 break; 
                     case LF_COMPLEX128:
	                     SetData(b.readByteArray(pos + 2, 32));
                    	 break; 
                     case LF_UTF8STRING:
                     case LF_VARSTRING:
                    	 int count = b.readUnsignedShort(pos + 2);
                    	 _rawSize += 2;
                    	 SetData(b.readByteArray(pos + 4, count));
                    	 break;                   
				}
			}
		}
	}
	
	public class LeafPointerAttr
    {
		public PointerType ptrtype;
        public PointerMode ptrmode;
        public boolean isflat32;
        public boolean isvolatile;
        public boolean isconst;
        public boolean isunaligned;
        public boolean isrestrict;        
        public int _raw;
        public LeafPointerAttr(long attr)
        {
			ptrtype = PointerType.getByValue(Helper.GetBits(attr, 0, 5));
            ptrmode = PointerMode.getByValue(Helper.GetBits(attr, 5, 3));
            isflat32 = Helper.GetBits(attr, 8, 1) != 0;
            isvolatile = Helper.GetBits(attr, 9, 1) != 0;
            isconst = Helper.GetBits(attr, 10, 1) != 0;
            isunaligned = Helper.GetBits(attr, 11, 1) != 0;
            isrestrict = Helper.GetBits(attr, 12, 1) != 0;
        }		
    }
	
	public class MR_Enumerate extends MemberRecord
	{
		public FieldAttribute attr;
		public Value val;
		public String name;
		public MR_Enumerate(BinaryReader b, long pos) throws Exception
		{
			recordKind = MemberRecordKind.LF_ENUMERATE;
			attr = new FieldAttribute(b.readUnsignedShort(pos));
			val = new Value(b, pos + 2);
			name = Helper.ReadCString(b, pos + 2 + val._rawSize);
		}

		@Override
		public long GetSize() {
			return 3 + val._rawSize + name.length();
		}		
	}
	
	public class MR_Member extends MemberRecord
	{
		public FieldAttribute attr;
        public long index;
        public Value offset;
        public String name;
         
		public MR_Member(BinaryReader b, long pos) throws Exception
		{
			recordKind = MemberRecordKind.LF_MEMBER;
			attr = new FieldAttribute(b.readUnsignedShort(pos));
			index = b.readUnsignedInt(pos + 2);
			offset = new Value(b, pos + 6);
			name = Helper.ReadCString(b, pos + 6 + offset._rawSize);
		}

		@Override
		public long GetSize() {
			return 7 + offset._rawSize + name.length();
		}		
	}
	
	public class LR_FieldList extends LeafRecord
	{
		public ArrayList<MemberRecord> records;
		public LR_FieldList(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			long pos = 0;
			records = new ArrayList<TypeRecord.MemberRecord>();
			boolean exit = false;
			while(pos < data.length && !exit)
			{
				MemberRecordKind k = MemberRecordKind.getByValue(b.readUnsignedShort(pos));
				if(k == null)
					return;
				pos += 2;
				switch(k)
				{
					case LF_ENUMERATE:
						MR_Enumerate mr_e = new MR_Enumerate(b, pos);
						pos += mr_e.GetSize();
						records.add(mr_e);
						break;
					case LF_MEMBER:
						MR_Member mr_m = new MR_Member(b, pos);
						pos += mr_m.GetSize();
						records.add(mr_m);
						break;
					default:	
						exit = true;
						break;
				}
				while((pos % 4) != 0)
					pos++;
			}
		}
	}
	
	public class LR_Enum extends LeafRecord
	{
		public int count;
		public Property property;
		public long utype;
		public long field;
		public String name;
		
		public LR_Enum(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			count = b.readUnsignedShort(0);
			property = new Property(b.readUnsignedShort(2));
			utype = b.readUnsignedInt(4);
			field = b.readUnsignedInt(8);
			name = Helper.ReadCString(b, 12);
		}
	}
	
	public class LR_Structure extends LeafRecord
	{
		public int count;
        public Property property;
        public long field;
        public long derived;
        public long vshape;
        public Value val;
        public String name;
        public String uniquename;
		
		public LR_Structure(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			count = b.readUnsignedShort(0);
            property = new Property(b.readUnsignedShort(2));
            field = b.readUnsignedInt(4);
            derived = b.readUnsignedInt(8);
            vshape = b.readUnsignedInt(12);
            val = new Value(b, 16);
            name = Helper.ReadCString(b, 16 + val._rawSize);
            if(property.hasuniquename)
            	uniquename = Helper.ReadCString(b, 17 + val._rawSize + name.length());
		}
	}
	
	public class LR_Pointer extends LeafRecord
	{
		public long type;
        public LeafPointerAttr attr;
		
		public LR_Pointer(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			type = b.readUnsignedInt(0);
			attr = new LeafPointerAttr(b.readUnsignedInt(4));
		}
	}

	public class LR_Array extends LeafRecord
	{
		public long elemtype;
	    public long idxtype;
	    public Value val;
	    public String name;
		
		public LR_Array(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			elemtype = b.readUnsignedInt(0);
			idxtype = b.readUnsignedInt(4);
			val = new Value(b, 8);
			name = Helper.ReadCString(b, 8 + val._rawSize);			
		}
	}

	public class LR_Bitfield extends LeafRecord
	{
		public long type;
        public int length;
        public int position;
		
		public LR_Bitfield(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			type = b.readUnsignedInt(0);
			length = b.readUnsignedByte(4);
			position = b.readUnsignedByte(5);
		}
	}

	public class LR_Union extends LeafRecord
	{
		public int count;
        public Property property;
        public long field;
        public Value val;
        public String name;
        public String uniquename;
		
		public LR_Union(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			count = b.readUnsignedShort(0);
			property = new Property(b.readUnsignedShort(2));
			field = b.readUnsignedInt(4);
			val = new Value(b, 8);
			name = Helper.ReadCString(b, 8 + val._rawSize);
            if(property.hasuniquename)
            	uniquename = Helper.ReadCString(b, 9 + val._rawSize + name.length());
		}
	}

	public class LR_ArgList extends LeafRecord
	{
        public long count;
        public long[] arg;
		
		public LR_ArgList(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			count = b.readUnsignedInt(0);
			arg = new long[(int)count];
			for(int i = 0; i < count; i++)
				arg[i] = b.readUnsignedInt(i * 4 + 4);
		}
	}

	public class LR_Procedure extends LeafRecord
	{
		public long rvtype;
        public int calltype;
        public int reserved;
        public int parmcount;
        public long arglist;
		
		public LR_Procedure(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			rvtype = b.readUnsignedInt(0);
			calltype = b.readUnsignedByte(4);
			reserved = b.readUnsignedByte(5);
			parmcount = b.readUnsignedShort(6);
			arglist = b.readUnsignedInt(8);
		}
	}

	public class LR_MemberFunction extends LeafRecord
	{
		public long rvtype;
        public long classtype;
        public long thistype;
        public CallType calltype;
        public int reserved;
        public int parmcount;
        public long arglist;
		
		public LR_MemberFunction(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			rvtype = b.readUnsignedInt(0);
			classtype = b.readUnsignedInt(4);
			thistype = b.readUnsignedInt(8);
			calltype = CallType.getByValue(b.readUnsignedByte(12));
			reserved = b.readUnsignedByte(13);
			parmcount = b.readUnsignedShort(14);
			arglist = b.readUnsignedInt(16);
		}
	}

	public class LR_Modifier extends LeafRecord
	{
        public long type;
        public ModAttr attr;
		
		public LR_Modifier(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			type = b.readUnsignedInt(0);
			attr = ModAttr.getByValue(b.readUnsignedShort(4));
		}
	}

	public class LR_MethodList extends LeafRecord
	{
        public class Method
        {
            public FieldAttribute attr;
            public long index;
            public long vbaseoff;
            public int _rawSize;
            public Method(BinaryReader b, int pos) throws Exception
            {
                attr = new FieldAttribute(b.readUnsignedShort(pos));
                index = b.readUnsignedInt(pos + 4);
                _rawSize = 8;
                if(attr.mprop == MProp.MTintro || attr.mprop == MProp.MTpureintro)
                {
                    vbaseoff = b.readUnsignedInt(pos + 8);
                	_rawSize = 12;
                }
            }
        }
        
        public ArrayList<Method> methods;
		
		public LR_MethodList(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			methods = new ArrayList<Method>();
			int pos = 0;
			while(pos < data.length)
			{
				Method m = new Method(b, pos);
				pos += m._rawSize;
				methods.add(m);
			}
		}
	}
	
	public class LR_VTShape extends LeafRecord
	{
		public ArrayList<Shape> shapes;
		
		public LR_VTShape(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			int count = b.readUnsignedShort(0);
			int bcount = count / 2;
			if((count % 2) != 0)
				bcount++;
			shapes = new ArrayList<Shape>();
			for(int i = 0; i < bcount; i++)
			{
				int d = b.readUnsignedByte(2 + i);
				shapes.add(Shape.getByValue(d >> 4));
				if(shapes.size() == count)
					break;
				shapes.add(Shape.getByValue(d & 0xf));
			}
		}
	}
	
	public class LR_Class extends LeafRecord
	{		
        public int count;
        public Property property;
        public long field;
        public long derived;
        public long vshape;
        public Value val;
        public String name;
        public String uniquename;
		public LR_Class(byte[] data) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			count = b.readUnsignedShort(0);
			property = new Property(b.readUnsignedShort(2));
			field = b.readUnsignedInt(4);
			derived = b.readUnsignedInt(8);
			vshape = b.readUnsignedInt(12);
			val = new Value(b, 16);
			name = Helper.ReadCString(b, 16 + val._rawSize);
            if(property.hasuniquename)
            	uniquename = Helper.ReadCString(b, 17 + val._rawSize + name.length());
		}
	}
	
    public long typeID;
	public LeafRecordKind kind;
	public LeafRecord record;
	
	public TypeRecord(long ID, int k, byte[] data) throws Exception
	{
		typeID = ID;
		kind = LeafRecordKind.getByValue(k);
		if(kind != null)
			switch(kind)
			{
				case LF_FIELDLIST:
					record = new LR_FieldList(data);
					break;
				case LF_ENUM:
					record = new LR_Enum(data);
					break;
				case LF_STRUCTURE:
					record = new LR_Structure(data);
					break;
				case LF_POINTER:
					record = new LR_Pointer(data);
					break;
				case LF_ARRAY:
					record = new LR_Array(data);
					break;
				case LF_BITFIELD:
					record = new LR_Bitfield(data);
					break;
				case LF_UNION:
					record = new LR_Union(data);
					break;
				case LF_ARGLIST:
					record = new LR_ArgList(data);
					break;
				case LF_PROCEDURE:
					record = new LR_Procedure(data);
					break;
				case LF_MFUNCTION:
					record = new LR_MemberFunction(data);
					break;
				case LF_MODIFIER:
					record = new LR_Modifier(data);
					break;
				case LF_METHODLIST:
					record = new LR_MethodList(data);		
					break;
				case LF_VTSHAPE:
					record = new LR_VTShape(data);
					break;
				case LF_CLASS:
					record = new LR_Class(data);
					break;
				default:
					record = null;
					break;
			}
	}
}


package xexloaderwv;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordCategory;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class XEXPdbTypeResolver {

	private static final class FieldListCounts {
		int physicalMembers;
		int staticMembers;
		int nestedTypes;
		int enumerators;
		int methods;
		final List<AbstractBaseClassMsType> bases = new ArrayList<>();
		final List<AbstractVirtualFunctionTablePointerMsType> vfptrs = new ArrayList<>();

		int total() {
			return physicalMembers + staticMembers + nestedTypes + enumerators + methods + bases.size() + vfptrs.size();
		}

		boolean hasDeclarations() {
			return staticMembers + nestedTypes + enumerators + methods + bases.size() + vfptrs.size() > 0;
		}

		String describe() {
			return "\nOriginal field-list entries: " + total() + "\nPhysical members: " + physicalMembers
					+ "\nStatic member declarations: " + staticMembers + "\nNested type declarations: " + nestedTypes
					+ "\nEnumerator declarations: " + enumerators + "\nMethod declarations: " + methods
					+ "\nDirect base classes: " + bases.size() + "\nExplicit virtual table pointers: " + vfptrs.size();
		}
	}

	public static class UnsupportedTypeException extends Exception {
		private static final long serialVersionUID = 1L;

		public UnsupportedTypeException(String message) {
			super(message);
		}
	}

	private static final CategoryPath CATEGORY = new CategoryPath("/XEX/PDB");
	private static final int MAX_TYPE_SIZE = 16 * 1024 * 1024;
	private static final int MAX_DEPTH = 64;
	private static final int POINTER_SIZE = 4;
	private final XEXPdbTypeCatalog catalog;
	private final DataTypeManager dtm;
	private final TaskMonitor monitor;
	private final Map<Integer, DataType> resolved = new HashMap<>();
	private final Map<Integer, Composite> shells = new TreeMap<>();
	private final Set<Integer> active = new HashSet<>();
	private final Set<Integer> pointerRecords = new HashSet<>();
	private final Set<Integer> vfptrLayouts = new HashSet<>();
	private final Set<Integer> emptyLeafLayouts = new HashSet<>();
	private final Map<Integer, FunctionDefinitionDataType> procedures = new TreeMap<>();
	private final Map<Integer, Prototype> memberPrototypes = new TreeMap<>();

	private record Member(int offset, String name, DataType type, int recordIndex, int bitPosition, int bitSize) {
		boolean isBitField() {
			return bitSize > 0;
		}

		int storageSize() {
			return type.getLength();
		}

		long startBit() {
			long start = (long) offset * 8;
			if (isBitField())
				start += storageSize() * 8 - bitPosition - bitSize;
			return start;
		}

		long endBit() {
			return startBit() + (isBitField() ? bitSize : (long) storageSize() * 8);
		}

		int componentOffset() {
			if (!isBitField())
				return offset;
			return offset + storageSize() - (bitPosition + bitSize + 7) / 8;
		}

		int componentLength() {
			if (!isBitField())
				return storageSize();
			return (bitPosition % 8 + bitSize + 7) / 8;
		}
	}

	public record Prototype(int typeIndex, int ownerIndex, int thisIndex, int thisAdjuster,
			CallingConvention convention, FunctionDefinitionDataType signature, Pointer thisPointer) {
		public boolean isMemberFunction() {
			return ownerIndex != 0;
		}

		public boolean hasThisPointer() {
			return thisPointer != null;
		}
	}

	public XEXPdbTypeResolver(XEXPdbTypeCatalog catalog, DataTypeManager dtm, TaskMonitor monitor) {
		this.catalog = catalog;
		this.dtm = dtm;
		this.monitor = monitor;
		if (dtm.getDataOrganization().getPointerSize() != POINTER_SIZE)
			throw new IllegalArgumentException("Expected 32-bit Xbox pointers");
	}

	public Map<Integer, DataType> buildTypes(MessageLog log) throws CancelledException {
		Map<Integer, DataType> result = new TreeMap<>();
		Map<String, Integer> failures = new TreeMap<>();
		int candidates = 0;
		int rejected = 0;
		int structures = 0;
		int unions = 0;
		int enums = 0;
		var definitions = catalog.getDefinitions();
		monitor.initialize(definitions.size());
		monitor.setMessage("Reconstructing PDB data types");
		for (var entry : definitions) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (entry.kind() != 0x1504 && entry.kind() != 0x1505 && entry.kind() != 0x1506 && entry.kind() != 0x1507)
				continue;
			candidates++;
			try {
				DataType type = resolve(RecordNumber.typeRecordNumber(entry.index()));
				result.put(entry.index(), type);
				if (type instanceof Structure)
					structures++;
				else if (type instanceof Union)
					unions++;
				else if (type instanceof EnumDataType)
					enums++;
			} catch (UnsupportedTypeException ex) {
				rejected++;
				failures.merge(ex.getMessage(), 1, Integer::sum);
			} catch (IllegalArgumentException | ArithmeticException ex) {
				rejected++;
				failures.merge("Invalid layout or numeric value", 1, Integer::sum);
			}
		}
		int incomplete = 0;
		for (var entry : shells.entrySet()) {
			monitor.checkCancelled();
			if (!resolved.containsKey(entry.getKey()))
				incomplete++;
		}
		log.appendMsg("PDB type candidates: " + candidates);
		log.appendMsg("PDB reconstructed types: " + result.size());
		log.appendMsg("PDB reconstructed structures: " + structures);
		log.appendMsg("PDB reconstructed unions: " + unions);
		log.appendMsg("PDB reconstructed enums: " + enums);
		log.appendMsg("PDB deferred types: " + rejected);
		log.appendMsg("PDB resolved pointer records: " + pointerRecords.size());
		log.appendMsg("PDB composite identities created: " + shells.size());
		log.appendMsg("PDB incomplete composite identities: " + incomplete);
		log.appendMsg("PDB reconstructed procedure types: " + procedures.size());
		for (var failure : failures.entrySet())
			log.appendMsg("PDB deferred: " + failure.getKey() + ": " + failure.getValue());
		return Collections.unmodifiableMap(result);
	}

	private DataType resolve(RecordNumber number) throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		int index = catalog.canonicalIndex(number.getNumber());
		DataType cached = resolved.get(index);
		if (cached != null)
			return cached;
		if (catalog.isUnresolvedForward(index))
			throw new UnsupportedTypeException("Unresolved by-value forward declaration");
		if (active.size() >= MAX_DEPTH || !active.add(index))
			throw new UnsupportedTypeException("Recursive or excessive by-value dependency");
		try {
			AbstractMsType raw = catalog.getRecord(number);
			DataType result;
			if (raw instanceof PrimitiveMsType) {
				result = primitive(index);
				if (result.getLength() != raw.getSize().intValueExact())
					throw new UnsupportedTypeException("Primitive size mismatch");
				if ((index & 0xff00) == 0x0400)
					pointerRecords.add(index);
			} else if (raw instanceof AbstractModifierMsType modifier) {
				result = resolve(modifier.getModifiedRecordNumber());
			} else if (raw instanceof AbstractPointerMsType pointer) {
				result = pointer(pointer);
				pointerRecords.add(index);
			} else if (raw instanceof ArrayMsType array) {
				result = array(array);
			} else if (raw instanceof AbstractUnionMsType union) {
				result = composite(index, union, true);
			} else if (raw instanceof AbstractStructureMsType || raw instanceof AbstractClassMsType) {
				result = composite(index, (AbstractCompositeMsType) raw, false);
			} else if (raw instanceof AbstractEnumMsType enumeration) {
				result = enumeration(index, enumeration);
			} else {
				throw new UnsupportedTypeException(
						"Unsupported record: " + (raw == null ? "null" : raw.getClass().getSimpleName()));
			}
			resolved.put(index, result);
			return result;
		} finally {
			active.remove(index);
		}
	}

	private String typeName(int index, String original) {
		String safeName = original == null || original.isBlank() ? "unnamed"
				: original.replaceAll("[^A-Za-z0-9_]", "_");
		if (safeName.length() > 120)
			safeName = safeName.substring(0, 120);
		return safeName + String.format("__TPI_%08X", index);
	}

	private String description(int index, String name, boolean incomplete) {
		return (incomplete ? "Incomplete PDB type: " : "Original PDB type: ") + name
				+ String.format("\nTPI index: 0x%X", index);
	}

	private Composite shell(int index, String name, boolean union) {
		return shells.computeIfAbsent(index, key -> {
			Composite type = union ? new UnionDataType(CATEGORY, typeName(key, name), dtm)
					: new StructureDataType(CATEGORY, typeName(key, name), 0, dtm);
			type.setPackingEnabled(false);
			type.setDescription(description(key, name, true));
			return type;
		});
	}

	private DataType pointerTarget(RecordNumber number) throws UnsupportedTypeException, CancelledException {
		Set<Integer> visited = new HashSet<>();
		while (true) {
			monitor.checkCancelled();
			int index = catalog.canonicalIndex(number.getNumber());
			if (visited.size() >= MAX_DEPTH || !visited.add(index))
				throw new UnsupportedTypeException("Invalid pointer target dependency");
			if (index == 0x0003)
				return VoidDataType.dataType.clone(dtm);
			var raw = catalog.getRecord(number);
			if (raw instanceof AbstractModifierMsType modifier) {
				number = modifier.getModifiedRecordNumber();
				continue;
			}
			if (raw instanceof AbstractUnionMsType)
				return shell(index, raw.getName(), true);
			if (raw instanceof AbstractStructureMsType || raw instanceof AbstractClassMsType)
				return shell(index, raw.getName(), false);
			if (raw instanceof AbstractProcedureMsType)
				return resolveProcedure(number);
			return resolve(number);
		}
	}

	private DataType pointer(AbstractPointerMsType raw) throws UnsupportedTypeException, CancelledException {
		if (raw.getPointerMode() != AbstractPointerMsType.MsPointerMode.POINTER)
			throw new UnsupportedTypeException("Unsupported pointer mode");
		if (raw.getPointerType() != AbstractPointerMsType.PointerType.NEAR32
				|| raw.getSize().intValueExact() != POINTER_SIZE)
			throw new UnsupportedTypeException("Unsupported pointer representation");
		DataType target = pointerTarget(raw.getUnderlyingRecordNumber());
		return new PointerDataType(target, POINTER_SIZE, dtm);
	}

	private DataType primitive(int index) throws UnsupportedTypeException {
		if ((index & 0xff00) == 0x0400) {
			int targetIndex = index & 0xff;
			DataType target = targetIndex == 0x03 ? VoidDataType.dataType.clone(dtm) : primitive(targetIndex);
			return new PointerDataType(target, POINTER_SIZE, dtm);
		}
		if (index == 0x0008) {
			return new TypedefDataType(new CategoryPath("/XEX/PDB/Primitives"), "HRESULT",
					SignedDWordDataType.dataType.clone(dtm), dtm);
		}
		DataType type = switch (index) {
		case 0x10, 0x68 -> SignedByteDataType.dataType;
		case 0x20, 0x69 -> ByteDataType.dataType;
		case 0x11, 0x72 -> SignedWordDataType.dataType;
		case 0x21, 0x73 -> WordDataType.dataType;
		case 0x12, 0x74 -> SignedDWordDataType.dataType;
		case 0x22, 0x75 -> DWordDataType.dataType;
		case 0x13, 0x76 -> SignedQWordDataType.dataType;
		case 0x23, 0x77 -> QWordDataType.dataType;
		case 0x30 -> BooleanDataType.dataType;
		case 0x40 -> FloatDataType.dataType;
		case 0x41 -> DoubleDataType.dataType;
		case 0x70 -> CharDataType.dataType;
		case 0x71 -> WideChar16DataType.dataType;
		default -> null;
		};
		if (type == null)
			throw new UnsupportedTypeException(String.format("Unsupported primitive type: 0x%04X", index));
		return type.clone(dtm);
	}

	private DataType array(ArrayMsType raw) throws UnsupportedTypeException, CancelledException {
		int size = raw.getSize().intValueExact();
		DataType element = resolve(raw.getElementTypeRecordNumber());
		int elementSize = element.getLength();
		if (size <= 0 || size > MAX_TYPE_SIZE || elementSize <= 0 || size % elementSize != 0)
			throw new UnsupportedTypeException("Invalid or unsupported array geometry");
		DataType result = new ArrayDataType(element, size / elementSize, elementSize, dtm);
		if (result.getLength() != size)
			throw new UnsupportedTypeException("Reconstructed array size mismatch");
		return result;
	}

	private void collectMembers(RecordNumber number, List<AbstractMemberMsType> members, Set<Integer> visited,
			FieldListCounts counts) throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		if (visited.size() >= MAX_DEPTH || !visited.add(number.getNumber()))
			throw new UnsupportedTypeException("Invalid field-list continuation");
		var raw = catalog.getRecord(number);
		if (!(raw instanceof AbstractFieldListMsType fields))
			throw new UnsupportedTypeException("Missing field list");
		for (var base : fields.getBaseClassList()) {
			monitor.checkCancelled();
			if (base instanceof AbstractBaseClassMsType direct)
				counts.bases.add(direct);
			else
				throw new UnsupportedTypeException("Virtual inheritance deferred");
		}
		counts.vfptrs.addAll(fields.getVftPointers());
		members.addAll(fields.getNonStaticMembers());
		counts.physicalMembers += fields.getNonStaticMembers().size();
		counts.staticMembers += fields.getStaticMembers().size();
		counts.nestedTypes += fields.getNestedTypes().size();
		counts.enumerators += fields.getEnumerates().size();
		for (var method : fields.getMethodList()) {
			monitor.checkCancelled();
			if (method instanceof AbstractOneMethodMsType) {
				counts.methods++;
			} else if (method instanceof AbstractOverloadedMethodMsType overloaded) {
				int count = overloaded.getCount();
				var methodList = catalog.getRecord(overloaded.getTypeMethodListRecordNumber());
				if (!(methodList instanceof AbstractMethodListMsType list) || count <= 0 || list.getListSize() != count)
					throw new UnsupportedTypeException("Invalid overloaded method list");
				counts.methods += count;
			} else {
				throw new UnsupportedTypeException("Unsupported method declaration");
			}
		}
		for (var continuation : fields.getIndexList())
			collectMembers(continuation.getReferencedRecordNumber(), members, visited, counts);
	}

	private DataType composite(int index, AbstractCompositeMsType raw, boolean union)
			throws UnsupportedTypeException, CancelledException {
		int size = raw.getSize().intValueExact();
		if (size <= 0 || size > MAX_TYPE_SIZE)
			throw new UnsupportedTypeException("Invalid or unsupported composite size");
		List<AbstractMemberMsType> original = new ArrayList<>();
		FieldListCounts counts = new FieldListCounts();
		RecordNumber fieldList = raw.getFieldDescriptorListRecordNumber();
		if (fieldList == null)
			throw new UnsupportedTypeException("Missing field-list reference");
		if (fieldList.getNumber() != 0) {
			collectMembers(fieldList, original, new HashSet<>(), counts);
		} else if (raw.getNumElements() != 0) {
			throw new UnsupportedTypeException("Missing nonempty field list");
		}
		if (counts.total() != raw.getNumElements())
			throw new UnsupportedTypeException("Original field-list count mismatch");
		if (original.size() != counts.physicalMembers)
			throw new UnsupportedTypeException("Physical member count mismatch");
		if (union && (!counts.bases.isEmpty() || !counts.vfptrs.isEmpty()))
			throw new UnsupportedTypeException("Unsupported union inheritance");
		List<Member> members = new ArrayList<>();
		boolean hasVfptr = !counts.vfptrs.isEmpty();
		for (var base : counts.bases) {
			Member member = resolveBase(base);
			members.add(member);
			if (vfptrLayouts.contains(catalog.canonicalIndex(member.recordIndex())))
				hasVfptr = true;
		}
		for (var vfptr : counts.vfptrs)
			members.add(resolveVfptr(vfptr));
		for (var field : original)
			members.add(resolveMember(field));
		if (!union) {
			RecordNumber shape = raw.getVShapeTableRecordNumber();
			if (shape != null && shape.getNumber() != 0) {
				var shapeType = catalog.getRecord(shape);
				if (shapeType == null || shapeType.getPdbId() != 0x000A)
					throw new UnsupportedTypeException("Invalid virtual table shape");
				if (!hasVfptr)
					throw new UnsupportedTypeException("Unresolved virtual table pointer");
			}
		}
		if (members.isEmpty()) {
			if (raw.getMsProperty().isForwardReference())
				throw new UnsupportedTypeException("Incomplete empty type");
			if (union)
				throw new UnsupportedTypeException("Empty union deferred");
			if (size != 1)
				throw new UnsupportedTypeException("Empty structure with unexplained size");
		}
		Member sharedEmptyBase = union ? null : removeSharedEmptyBase(members, counts, size);
		Set<String> names = new HashSet<>();
		Map<String, Member> unionBitfields = new HashMap<>();
		int largest = 0;
		for (int i = 0; i < members.size(); i++) {
			Member member = members.get(i);
			monitor.checkCancelled();
			int offset = member.offset();
			int length = member.storageSize();
			String name = member.name();
			if (name == null || name.isBlank() || !names.add(name))
				throw new UnsupportedTypeException("Missing or duplicate member name");
			if (offset < 0 || length <= 0 || (long) offset + length > size)
				throw new UnsupportedTypeException("Member exceeds composite bounds");
			if (union && offset != 0)
				throw new UnsupportedTypeException("Nonzero union member offset");
			if (union && member.isBitField()) {
				unionBitfields.put(member.name(), member);
				member = wrapUnionBitfield(index, i, member);
				members.set(i, member);
			}
			largest = Math.max(largest, length);
		}
		if (union) {
			if (largest != size)
				throw new UnsupportedTypeException("Union size exceeds largest member");
		} else {
			members.sort(Comparator.comparingLong(Member::startBit));
			long end = 0;
			for (var member : members) {
				if (member.startBit() < end)
					throw new UnsupportedTypeException("Overlapping structure or base members");
				if (member.endBit() > (long) size * 8)
					throw new UnsupportedTypeException("Member exceeds bit boundary");
				end = member.endBit();
			}
		}
		Composite result = shell(index, raw.getName(), union);
		boolean completed = false;
		try {
			if (result instanceof StructureDataType structure)
				structure.setLength(size);
			for (var member : members) {
				monitor.checkCancelled();
				String comment = String.format("PDB type index: 0x%X", member.recordIndex());
				if (member.name().startsWith("__base_"))
					comment += "; fixed-offset base class";
				else if (member.name().startsWith("__vfptr_"))
					comment += "; virtual function table pointer; slots unresolved";
				if (result instanceof StructureDataType structure) {
					if (member.isBitField()) {
						comment += String.format("; storage offset: 0x%X; bit position: %d; bit size: %d",
								member.offset(), member.bitPosition(), member.bitSize());
						structure.insertBitFieldAt(member.offset(), member.storageSize(), member.bitPosition(),
								member.type(), member.bitSize(), member.name(), comment);
					} else {
						structure.replaceAtOffset(member.offset(), member.type(), -1, member.name(), comment);
					}
				} else if (result instanceof UnionDataType unionType) {
					unionType.add(member.type(), member.storageSize(), member.name(), comment);
				}
			}
			validateComposite(result, size, members);
			if (!unionBitfields.isEmpty()) {
				for (var component : result.getComponents()) {
					monitor.checkCancelled();
					Member originalBitfield = unionBitfields.get(component.getFieldName());
					if (originalBitfield == null)
						continue;
					if (!(component.getDataType() instanceof Structure view))
						throw new UnsupportedTypeException("Missing union bitfield view");
					validateComposite(view, originalBitfield.storageSize(), List.of(originalBitfield));
				}
			}
			if (members.isEmpty()) {
				if (result.isZeroLength() || result.isNotYetDefined() || result.getLength() != 1
						|| result.getNumDefinedComponents() != 0)
					throw new UnsupportedTypeException("Invalid empty structure representation");
			}
			String description = description(index, raw.getName(), false);
			if (counts.hasDeclarations())
				description += counts.describe();
			if (hasVfptr)
				description += "\nVirtual function table slots not reconstructed.";
			if (members.isEmpty())
				description += "\nComplete empty C++ definition; one byte of object storage.";
			if (!unionBitfields.isEmpty())
				description += "\nDirect union bitfields represented by validated synthetic storage views: "
						+ unionBitfields.size();
			if (sharedEmptyBase != null) {
				description += String.format(
						"\nEmpty base class optimization:\nBase type: %s\nOriginal TPI index: 0x%X\n"
								+ "Canonical TPI index: 0x%X\nOriginal base offset: 0x%X\n"
								+ "No separate physical storage component.",
						sharedEmptyBase.type().getName(), sharedEmptyBase.recordIndex(),
						catalog.canonicalIndex(sharedEmptyBase.recordIndex()), sharedEmptyBase.offset());
			}
			result.setDescription(description);
			if (hasVfptr)
				vfptrLayouts.add(index);
			if (!union && members.isEmpty() && counts.bases.isEmpty() && counts.vfptrs.isEmpty() && !hasVfptr
					&& size == 1)
				emptyLeafLayouts.add(index);
			completed = true;
			return result;
		} catch (InvalidDataTypeException ex) {
			throw new UnsupportedTypeException("Ghidra rejected bitfield datatype");
		} finally {
			if (!completed) {
				vfptrLayouts.remove(index);
				emptyLeafLayouts.remove(index);
				if (result instanceof StructureDataType structure) {
					structure.deleteAll();
					structure.setLength(0);
				} else if (result instanceof UnionDataType unionType) {
					while (unionType.getNumComponents() > 0)
						unionType.delete(unionType.getNumComponents() - 1);
				}
				result.setDescription(description(index, raw.getName(), true));
			}
		}
	}

	private void validateComposite(Composite result, int size, List<Member> members) throws UnsupportedTypeException {
		if (result.getLength() != size)
			throw new UnsupportedTypeException("Reconstructed composite size mismatch");
		var components = result instanceof Structure structure ? structure.getDefinedComponents()
				: result.getComponents();
		if (components.length != members.size())
			throw new UnsupportedTypeException("Reconstructed member count mismatch");
		Map<String, DataTypeComponent> byName = new HashMap<>();
		for (var component : components) {
			String name = component.getFieldName();
			if (name == null || byName.put(name, component) != null)
				throw new UnsupportedTypeException("Invalid reconstructed member name");
		}
		for (var member : members) {
			var component = byName.get(member.name());
			if (component == null)
				throw new UnsupportedTypeException("Missing reconstructed member");
			if (component.getOffset() != member.componentOffset() || component.getLength() != member.componentLength())
				throw new UnsupportedTypeException("Reconstructed member geometry mismatch");
			if (member.isBitField()) {
				if (!(component.getDataType() instanceof BitFieldDataType bitfield))
					throw new UnsupportedTypeException("Missing reconstructed bitfield");
				if (bitfield.getBitSize() != member.bitSize() || bitfield.getDeclaredBitSize() != member.bitSize()
						|| bitfield.getBitOffset() != member.bitPosition() % 8
						|| bitfield.getBaseTypeSize() != member.storageSize()
						|| !bitfield.getBaseDataType().isEquivalent(member.type()))
					throw new UnsupportedTypeException("Reconstructed bitfield geometry mismatch");
			} else if (component.getDataType() instanceof BitFieldDataType) {
				throw new UnsupportedTypeException("Unexpected reconstructed bitfield");
			}
		}
	}

	private void collectEnumerators(RecordNumber number, List<AbstractEnumerateMsType> values, Set<Integer> visited)
			throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		if (visited.size() >= MAX_DEPTH || !visited.add(number.getNumber()))
			throw new UnsupportedTypeException("Invalid enum field-list continuation");
		var raw = catalog.getRecord(number);
		if (!(raw instanceof AbstractFieldListMsType fields))
			throw new UnsupportedTypeException("Missing enum field list");
		if (!fields.getBaseClassList().isEmpty() || !fields.getNonStaticMembers().isEmpty()
				|| !fields.getStaticMembers().isEmpty() || !fields.getMethodList().isEmpty()
				|| !fields.getNestedTypes().isEmpty() || !fields.getVftPointers().isEmpty())
			throw new UnsupportedTypeException("Unexpected enum field-list content");
		values.addAll(fields.getEnumerates());
		for (var continuation : fields.getIndexList())
			collectEnumerators(continuation.getReferencedRecordNumber(), values, visited);
	}

	private DataType enumeration(int index, AbstractEnumMsType raw)
			throws UnsupportedTypeException, CancelledException {
		RecordNumber underlying = raw.getUnderlyingRecordNumber();
		int underlyingIndex = underlying.getNumber();
		boolean signed = switch (underlyingIndex) {
		case 0x10, 0x68, 0x11, 0x72, 0x12, 0x74, 0x13, 0x76 -> true;
		case 0x20, 0x69, 0x21, 0x73, 0x22, 0x75, 0x23, 0x77 -> false;
		default -> throw new UnsupportedTypeException("Unsupported enum underlying type");
		};
		DataType storage = resolve(underlying);
		int size = storage.getLength();
		if (size != 1 && size != 2 && size != 4 && size != 8)
			throw new UnsupportedTypeException("Unsupported enum storage size");
		int bits = size * 8;
		BigInteger min = signed ? BigInteger.ONE.shiftLeft(bits - 1).negate() : BigInteger.ZERO;
		BigInteger max = BigInteger.ONE.shiftLeft(signed ? bits - 1 : bits).subtract(BigInteger.ONE);
		List<AbstractEnumerateMsType> original = new ArrayList<>();
		collectEnumerators(raw.getFieldDescriptorListRecordNumber(), original, new HashSet<>());
		if (original.isEmpty() || original.size() != raw.getNumElements())
			throw new UnsupportedTypeException("Incomplete or empty enumerator list");
		EnumDataType result = new EnumDataType(CATEGORY, typeName(index, raw.getName()), size, dtm);
		Map<String, Long> expected = new TreeMap<>();
		for (var enumerator : original) {
			monitor.checkCancelled();
			String name = enumerator.getName();
			var numeric = enumerator.getNumeric();
			if (name == null || name.isBlank() || expected.containsKey(name))
				throw new UnsupportedTypeException("Missing or duplicate enumerator name");
			if (!numeric.isIntegral())
				throw new UnsupportedTypeException("Nonintegral enumerator value");
			BigInteger value = numeric.getIntegral();
			if (value.compareTo(min) < 0 || value.compareTo(max) > 0)
				throw new UnsupportedTypeException("Enumerator exceeds underlying type range");
			if (value.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0)
				throw new UnsupportedTypeException("Unsigned 64-bit enumerator deferred");
			long exact = value.longValueExact();
			expected.put(name, exact);
			result.add(name, exact);
		}
		if (result.getLength() != size || result.getCount() != expected.size())
			throw new UnsupportedTypeException("Reconstructed enum geometry mismatch");
		for (var entry : expected.entrySet()) {
			if (result.getValue(entry.getKey()) != entry.getValue().longValue())
				throw new UnsupportedTypeException("Reconstructed enumerator value mismatch");
		}
		result.setDescription(
				description(index, raw.getName(), false) + String.format("\nUnderlying TPI type: 0x%X", underlyingIndex)
						+ "\nOriginal signedness: " + (signed ? "signed" : "unsigned"));
		return result;
	}

	private FunctionDefinitionDataType resolveProcedure(RecordNumber number)
			throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		int index = catalog.canonicalIndex(number.getNumber());
		FunctionDefinitionDataType cached = procedures.get(index);
		if (cached != null)
			return cached;
		if (active.size() >= MAX_DEPTH || !active.add(index))
			throw new UnsupportedTypeException("Recursive procedure dependency");
		try {
			var record = catalog.getRecord(number);
			if (!(record instanceof AbstractProcedureMsType raw))
				throw new UnsupportedTypeException("Invalid procedure record");
			var convention = raw.getCallingConvention();
			if (convention != CallingConvention.NEAR_C && convention != CallingConvention.PPCCALL)
				throw new UnsupportedTypeException("Unsupported procedure calling convention: " + convention.name());
			if (raw.getFunctionAttributes().isConstructor())
				throw new UnsupportedTypeException("Constructor procedure deferred");
			RecordNumber returnRecord = raw.getReturnRecordNumber();
			DataType returnType;
			if (returnRecord.getNumber() == 0x0003) {
				returnType = VoidDataType.dataType.clone(dtm);
			} else {
				returnType = resolve(returnRecord);
				if (returnType.getLength() <= 0 || returnType instanceof Array
						|| returnType instanceof FunctionDefinition)
					throw new UnsupportedTypeException("Invalid procedure return type");
			}
			RecordNumber listNumber = raw.getArgListRecordNumber();
			List<RecordNumber> arguments;
			if (listNumber.getNumber() == 0 && raw.getNumParams() == 0) {
				arguments = List.of();
			} else {
				var list = catalog.getRecord(listNumber);
				if (!(list instanceof AbstractArgumentsListMsType argumentList))
					throw new UnsupportedTypeException("Invalid procedure argument list");
				arguments = argumentList.getArgRecordNumbers();
			}
			if (arguments.size() != raw.getNumParams())
				throw new UnsupportedTypeException("Procedure parameter count mismatch");
			List<ParameterDefinition> parameters = new ArrayList<>();
			boolean varArgs = false;
			for (int i = 0; i < arguments.size(); i++) {
				monitor.checkCancelled();
				RecordNumber argument = arguments.get(i);
				if (argument.getNumber() == 0) {
					if (i != arguments.size() - 1)
						throw new UnsupportedTypeException("Invalid variadic argument marker");
					varArgs = true;
					continue;
				}
				DataType type = resolve(argument);
				if (type.getLength() <= 0 || type instanceof VoidDataType || type instanceof Array
						|| type instanceof FunctionDefinition)
					throw new UnsupportedTypeException("Invalid procedure argument type");
				parameters.add(new ParameterDefinitionImpl("param_" + (i + 1), type,
						String.format("Original TPI index: 0x%X", argument.getNumber())));
			}
			FunctionDefinitionDataType result = new FunctionDefinitionDataType(new CategoryPath("/XEX/PDB/Procedures"),
					String.format("Procedure__TPI_%08X", index), dtm);
			result.setReturnType(returnType);
			result.setArguments(parameters.toArray(new ParameterDefinition[0]));
			result.setVarArgs(varArgs);
			StringBuilder attributes = new StringBuilder();
			raw.getFunctionAttributes().emit(attributes);
			result.setComment(String.format(
					"Original procedure TPI index: 0x%X\nCodeView calling convention: %s (0x%02X)\n"
							+ "Original function attributes: %s\n"
							+ "Parameter names are synthetic; ABI mapping not yet verified.",
					index, convention.name(), convention.getValue(), attributes));
			if (result.hasVarArgs() != varArgs || result.getArguments().length != parameters.size())
				throw new UnsupportedTypeException("Reconstructed procedure geometry mismatch");
			if (result.getReturnType() != returnType && !result.getReturnType().isEquivalent(returnType))
				throw new UnsupportedTypeException("Reconstructed procedure return type mismatch");
			var actual = result.getArguments();
			for (int i = 0; i < actual.length; i++) {
				DataType expected = parameters.get(i).getDataType();
				DataType reconstructed = actual[i].getDataType();
				if (reconstructed.getLength() != expected.getLength()
						|| (reconstructed != expected && !reconstructed.isEquivalent(expected)))
					throw new UnsupportedTypeException("Reconstructed procedure argument mismatch");
			}
			procedures.put(index, result);
			return result;
		} finally {
			active.remove(index);
		}
	}

	private Member resolveMember(AbstractMemberMsType field) throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		int offset = field.getOffset().intValueExact();
		String name = field.getName();
		RecordNumber number = field.getFieldTypeRecordNumber();
		int index = number.getNumber();
		var raw = catalog.getRecord(number);
		if (raw instanceof AbstractBitfieldMsType bitfield) {
			if (!dtm.getDataOrganization().isBigEndian())
				throw new UnsupportedTypeException("Expected big-endian bitfield layout");
			DataType base = resolve(bitfield.getElementRecordNumber());
			if (!(base instanceof AbstractIntegerDataType))
				throw new UnsupportedTypeException("Unsupported bitfield base type");
			int storageSize = base.getLength();
			int position = bitfield.getBitPosition();
			int size = bitfield.getBitLength();
			if (storageSize != 1 && storageSize != 2 && storageSize != 4 && storageSize != 8)
				throw new UnsupportedTypeException("Unsupported bitfield storage size");
			if (position < 0 || size <= 0 || (long) position + size > storageSize * 8)
				throw new UnsupportedTypeException("Invalid bitfield geometry");
			return new Member(offset, name, base, index, position, size);
		}
		DataType type = resolve(number);
		return new Member(offset, name, type, index, 0, 0);
	}

	private Member wrapUnionBitfield(int index, int ordinal, Member member)
			throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		if (!member.isBitField() || member.offset() != 0)
			throw new UnsupportedTypeException("Invalid direct union bitfield");
		String name = String.format("Union_%08X_Field_%04X", index, ordinal);
		StructureDataType view = new StructureDataType(new CategoryPath("/XEX/PDB/UnionBitfields"), name,
				member.storageSize(), dtm);
		view.setPackingEnabled(false);
		view.setDescription(String.format(
				"Synthetic storage view for original union bitfield %s\n"
						+ "Owner TPI index: 0x%X\nBitfield TPI index: 0x%X\n"
						+ "Original bit position: %d\nOriginal bit size: %d",
				member.name(), index, member.recordIndex(), member.bitPosition(), member.bitSize()));
		try {
			view.insertBitFieldAt(0, member.storageSize(), member.bitPosition(), member.type(), member.bitSize(),
					member.name(), String.format("Original bitfield TPI index: 0x%X", member.recordIndex()));
		} catch (InvalidDataTypeException ex) {
			throw new UnsupportedTypeException("Invalid union bitfield datatype");
		}
		validateComposite(view, member.storageSize(), List.of(member));
		return new Member(0, member.name(), view, member.recordIndex(), 0, 0);
	}

	private Member removeSharedEmptyBase(List<Member> members, FieldListCounts counts, int size)
			throws CancelledException {
		monitor.checkCancelled();
		if (counts.bases.size() != 1 || !counts.vfptrs.isEmpty() || members.size() < 2)
			return null;
		Member base = members.get(0);
		int index = catalog.canonicalIndex(base.recordIndex());
		if (!emptyLeafLayouts.contains(index))
			return null;
		if (!(base.type() instanceof Structure structure) || structure.isZeroLength() || structure.getLength() != 1
				|| structure.getNumDefinedComponents() != 0)
			return null;
		if (base.offset() < 0 || base.offset() >= size)
			return null;
		for (int i = 1; i < members.size(); i++) {
			monitor.checkCancelled();
			Member member = members.get(i);
			if (member.isBitField() || member.offset() != base.offset())
				continue;
			if (member.storageSize() <= 0 || (long) member.offset() + member.storageSize() > size)
				continue;
			if (!(member.type() instanceof AbstractIntegerDataType) && !(member.type() instanceof Pointer))
				continue;
			members.remove(0);
			return base;
		}
		return null;
	}

	private Member resolveBase(AbstractBaseClassMsType base) throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		RecordNumber number = base.getBaseClassRecordNumber();
		int index = catalog.canonicalIndex(number.getNumber());
		int offset = base.getOffset().intValueExact();
		DataType type = resolve(number);
		if (!(type instanceof Structure) || type.getLength() <= 0)
			throw new UnsupportedTypeException("Invalid base class layout");
		String name = String.format("__base_%08X_%X", index, offset);
		return new Member(offset, name, type, number.getNumber(), 0, 0);
	}

	private Member resolveVfptr(AbstractVirtualFunctionTablePointerMsType field)
			throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		RecordNumber number = field.getPointerTypeRecordNumber();
		var raw = catalog.getRecord(number);
		if (!(raw instanceof AbstractPointerMsType pointer))
			throw new UnsupportedTypeException("Invalid virtual table pointer record");
		if (pointer.getPointerMode() != AbstractPointerMsType.MsPointerMode.POINTER
				|| pointer.getPointerType() != AbstractPointerMsType.PointerType.NEAR32
				|| pointer.getSize().intValueExact() != POINTER_SIZE)
			throw new UnsupportedTypeException("Unsupported virtual table pointer representation");
		var target = catalog.getRecord(pointer.getUnderlyingRecordNumber());
		if (target == null || target.getPdbId() != 0x000A)
			throw new UnsupportedTypeException("Unsupported virtual table pointer target");
		int offset = field.getOffset();
		String name = String.format("__vfptr_%X", offset);
		DataType type = new PointerDataType(VoidDataType.dataType.clone(dtm), POINTER_SIZE, dtm);
		return new Member(offset, name, type, number.getNumber(), 0, 0);
	}

	public Prototype reconstructPrototype(RecordNumber number) throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		int index = catalog.canonicalIndex(number.getNumber());
		var raw = catalog.getRecord(number);
		if (raw instanceof AbstractProcedureMsType procedure) {
			FunctionDefinitionDataType signature = resolveProcedure(number);
			return new Prototype(index, 0, 0, 0, procedure.getCallingConvention(), signature, null);
		}
		if (raw instanceof AbstractMemberFunctionMsType member)
			return resolveMemberPrototype(index, member);
		throw new UnsupportedTypeException("Unsupported function type record");
	}

	private Prototype resolveMemberPrototype(int index, AbstractMemberFunctionMsType raw)
			throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		Prototype cached = memberPrototypes.get(index);
		if (cached != null)
			return cached;
		if (active.size() >= MAX_DEPTH || !active.add(index))
			throw new UnsupportedTypeException("Recursive member function dependency");
		try {
			CallingConvention convention = raw.getCallingConvention();
			if (convention != CallingConvention.NEAR_C && convention != CallingConvention.PPCCALL)
				throw new UnsupportedTypeException("Unsupported member calling convention: " + convention.name());
			if (raw.isConstructor())
				throw new UnsupportedTypeException("Constructor prototype deferred");
			RecordNumber ownerRecord = raw.getContainingClassRecordNumber();
			if (ownerRecord == null || ownerRecord.getNumber() == 0)
				throw new UnsupportedTypeException("Missing member function owner");
			var owner = catalog.getRecord(ownerRecord);
			if (!(owner instanceof AbstractClassMsType || owner instanceof AbstractStructureMsType
					|| owner instanceof AbstractUnionMsType))
				throw new UnsupportedTypeException("Invalid member function owner");
			RecordNumber thisRecord = raw.getThisPointerRecordNumber();
			if (thisRecord == null)
				throw new UnsupportedTypeException("Missing this pointer record");
			int thisIndex = thisRecord.getNumber();
			Pointer thisPointer = null;
			if (thisIndex != 0) {
				DataType type = resolve(thisRecord);
				if (!(type instanceof Pointer pointer) || type.getLength() != POINTER_SIZE)
					throw new UnsupportedTypeException("Invalid member function this pointer");
				DataType ownerType = pointerTarget(ownerRecord);
				DataType target = pointer.getDataType();
				if (target == null || !target.getPathName().equals(ownerType.getPathName()))
					throw new UnsupportedTypeException("Member function this type mismatch");
				thisPointer = pointer;
			} else if (raw.getThisAdjuster() != 0) {
				throw new UnsupportedTypeException("Unexpected static function this adjustment");
			}
			RecordNumber returnRecord = raw.getReturnRecordNumber();
			DataType returnType;
			if (returnRecord.getNumber() == 0x0003) {
				returnType = VoidDataType.dataType.clone(dtm);
			} else {
				returnType = resolve(returnRecord);
				if (returnType.getLength() <= 0 || returnType instanceof Array
						|| returnType instanceof FunctionDefinition)
					throw new UnsupportedTypeException("Invalid member function return type");
			}
			RecordNumber listNumber = raw.getArgListRecordNumber();
			List<RecordNumber> arguments;
			if (listNumber.getNumber() == 0 && raw.getNumParams() == 0) {
				arguments = List.of();
			} else {
				var list = catalog.getRecord(listNumber);
				if (!(list instanceof AbstractArgumentsListMsType argumentList))
					throw new UnsupportedTypeException("Invalid member function argument list");
				arguments = argumentList.getArgRecordNumbers();
			}
			if (arguments.size() != raw.getNumParams())
				throw new UnsupportedTypeException("Member function parameter count mismatch");
			List<ParameterDefinition> parameters = new ArrayList<>();
			boolean varArgs = false;
			for (int i = 0; i < arguments.size(); i++) {
				monitor.checkCancelled();
				RecordNumber argument = arguments.get(i);
				if (argument.getNumber() == 0) {
					if (i != arguments.size() - 1)
						throw new UnsupportedTypeException("Invalid variadic member argument");
					varArgs = true;
					continue;
				}
				DataType type = resolve(argument);
				if (type.getLength() <= 0 || type instanceof VoidDataType || type instanceof Array
						|| type instanceof FunctionDefinition)
					throw new UnsupportedTypeException("Invalid member function argument type");
				parameters.add(new ParameterDefinitionImpl("param_" + (i + 1), type,
						String.format("Original TPI index: 0x%X", argument.getNumber())));
			}
			FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
					new CategoryPath("/XEX/PDB/MemberFunctions"), String.format("MemberFunction__TPI_%08X", index),
					dtm);
			signature.setReturnType(returnType);
			signature.setArguments(parameters.toArray(new ParameterDefinition[0]));
			signature.setVarArgs(varArgs);
			StringBuilder attributes = new StringBuilder();
			raw.getFunctionAttributes().emit(attributes);
			signature.setComment(String.format(
					"Original member function TPI index: 0x%X\n" + "Original owner: %s\n" + "Owner TPI index: 0x%X\n"
							+ "This pointer TPI index: 0x%X\n" + "This adjustment: %d\n"
							+ "CodeView calling convention: %s (0x%02X)\n" + "Original function attributes: %s\n"
							+ "Formal signature; implicit this stored separately.",
					index, owner.getName(), ownerRecord.getNumber(), thisIndex, raw.getThisAdjuster(),
					convention.name(), convention.getValue(), attributes));
			if (signature.hasVarArgs() != varArgs || signature.getArguments().length != parameters.size())
				throw new UnsupportedTypeException("Member function signature mismatch");
			if (!signature.getReturnType().isEquivalent(returnType))
				throw new UnsupportedTypeException("Member function return type mismatch");
			var actual = signature.getArguments();
			for (int i = 0; i < actual.length; i++) {
				DataType expected = parameters.get(i).getDataType();
				DataType reconstructed = actual[i].getDataType();
				if (reconstructed.getLength() != expected.getLength() || !reconstructed.isEquivalent(expected))
					throw new UnsupportedTypeException("Member function argument mismatch");
			}
			Prototype result = new Prototype(index, ownerRecord.getNumber(), thisIndex, raw.getThisAdjuster(),
					convention, signature, thisPointer);
			memberPrototypes.put(index, result);
			return result;
		} finally {
			active.remove(index);
		}
	}

	public DataType reconstructDataType(RecordNumber number) throws UnsupportedTypeException, CancelledException {
		monitor.checkCancelled();
		if (number == null || number.getCategory() != RecordCategory.TYPE || number.getNumber() <= 0)
			throw new UnsupportedTypeException("Invalid data type record");
		DataType type = resolve(number);
		if (type.getLength() <= 0 || type instanceof VoidDataType || type instanceof FunctionDefinition)
			throw new UnsupportedTypeException("Invalid variable data type");
		return type;
	}
}

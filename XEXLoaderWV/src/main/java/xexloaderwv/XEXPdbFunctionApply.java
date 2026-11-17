package xexloaderwv;

import java.util.ArrayList;
import java.util.List;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public final class XEXPdbFunctionApply {
	public enum Status {
		READY, APPLIED, NO_FUNCTION, PRESERVED, UNSUPPORTED_TYPE, UNSUPPORTED_ABI
	}

	public record Result(Status status, String message) {
	}

	private XEXPdbFunctionApply() {
	}

	private static boolean supportedScalar(DataType type) {
		int length = type.getLength();
		if (type instanceof Pointer)
			return length == 4;
		while (type instanceof TypeDef alias)
			type = alias.getBaseDataType();
		if (length != 1 && length != 2 && length != 4)
			return false;
		return type instanceof AbstractIntegerDataType || type instanceof BooleanDataType
				|| type instanceof CharDataType || type instanceof WideChar16DataType || type instanceof Enum;
	}

	private static boolean validRegisterStorage(Program program, VariableStorage storage, DataType type,
			int registerNumber) {
		if (storage == null)
			return false;
		if (type instanceof VoidDataType)
			return storage.isVoidStorage();
		if (!storage.isValid() || !storage.isRegisterStorage() || storage.isAutoStorage() || storage.isForcedIndirect()
				|| storage.size() != type.getLength())
			return false;
		var register = program.getLanguage().getRegister("r" + registerNumber);
		if (register == null || register.getMinimumByteSize() != 8)
			return false;
		var expected = register.getAddress().add(8 - type.getLength());
		return storage.getFirstVarnode().getAddress().equals(expected);
	}

	private static boolean sameType(DataType expected, DataType actual) {
		return expected.getLength() == actual.getLength() && expected.isEquivalent(actual);
	}

	public static Result process(Program program, XEXPdbTypeCatalog catalog, XEXPdbTypeResolver resolver,
			XEXPdbFunctionCatalog.FunctionEntry entry, boolean apply, TaskMonitor monitor) throws Exception {
		monitor.checkCancelled();
		if (!program.getLanguageID().getIdAsString().equals("PowerPC:BE:64:A2ALT-32addr")
				|| program.getDefaultPointerSize() != 4 || !program.getLanguage().isBigEndian())
			return new Result(Status.UNSUPPORTED_ABI, "Unsupported program architecture");
		var function = program.getFunctionManager().getFunctionAt(entry.address());
		if (function == null)
			return new Result(Status.NO_FUNCTION, "No exact function entry");
		if (function.isExternal() || function.isThunk() || function.hasCustomVariableStorage()
				|| function.getSignatureSource() != SourceType.DEFAULT || function.getParameterCount() != 0
				|| function.getLocalVariables().length != 0 || function.hasVarArgs())
			return new Result(Status.PRESERVED, "Existing function information preserved");
		if (entry.prototypeKind() == XEXPdbFunctionCatalog.PrototypeKind.UNSUPPORTED || entry.typeRecord() == null)
			return new Result(Status.UNSUPPORTED_TYPE, "Unsupported function record");
		var raw = catalog.getRecord(entry.typeRecord());
		StringBuilder attributes = new StringBuilder();
		if (raw instanceof AbstractProcedureMsType procedure) {
			procedure.getFunctionAttributes().emit(attributes);
		} else if (raw instanceof AbstractMemberFunctionMsType member) {
			member.getFunctionAttributes().emit(attributes);
		} else {
			return new Result(Status.UNSUPPORTED_TYPE, "Invalid prototype record");
		}
		if (!attributes.isEmpty())
			return new Result(Status.UNSUPPORTED_ABI, "Special function attributes deferred");
		XEXPdbTypeResolver.Prototype prototype;
		try {
			prototype = resolver.reconstructPrototype(entry.typeRecord());
		} catch (XEXPdbTypeResolver.UnsupportedTypeException ex) {
			return new Result(Status.UNSUPPORTED_TYPE, ex.getMessage());
		}
		if (prototype.thisAdjuster() != 0)
			return new Result(Status.UNSUPPORTED_ABI, "Nonzero this adjustment deferred");
		var signature = prototype.signature();
		if (signature.hasVarArgs())
			return new Result(Status.UNSUPPORTED_ABI, "Variadic function deferred");
		DataType returnType = signature.getReturnType();
		if (!(returnType instanceof VoidDataType) && !supportedScalar(returnType))
			return new Result(Status.UNSUPPORTED_ABI, "Unsupported return type");
		List<DataType> types = new ArrayList<>();
		List<String> names = new ArrayList<>();
		types.add(returnType);
		if (prototype.hasThisPointer()) {
			if (prototype.thisPointer().getLength() != 4)
				return new Result(Status.UNSUPPORTED_ABI, "Invalid this pointer size");
			types.add(prototype.thisPointer());
			names.add("this_ptr");
		}
		for (var argument : signature.getArguments()) {
			monitor.checkCancelled();
			DataType type = argument.getDataType();
			if (!supportedScalar(type))
				return new Result(Status.UNSUPPORTED_ABI, "Unsupported parameter type");
			types.add(type);
			names.add("param_" + (names.size() + 1));
		}
		if (names.size() > 8)
			return new Result(Status.UNSUPPORTED_ABI, "Stack parameters deferred");
		var model = program.getCompilerSpec().getDefaultCallingConvention();
		if (model == null || !"__stdcall".equals(model.getName()))
			return new Result(Status.UNSUPPORTED_ABI, "Unexpected PowerPC prototype model");
		var convention = function.getCallingConvention();
		if (convention != null && !model.getName().equals(convention.getName()))
			return new Result(Status.PRESERVED, "Existing calling convention preserved");
		DataType[] typeArray = types.toArray(new DataType[0]);
		VariableStorage[] storage = model.getStorageLocations(program, typeArray, false, false);
		if (storage == null || storage.length != typeArray.length)
			return new Result(Status.UNSUPPORTED_ABI, "Unexpected automatic parameters");
		if (!validRegisterStorage(program, storage[0], returnType, 3))
			return new Result(Status.UNSUPPORTED_ABI, "Unexpected return storage");
		for (int i = 0; i < names.size(); i++) {
			monitor.checkCancelled();
			if (!validRegisterStorage(program, storage[i + 1], types.get(i + 1), i + 3))
				return new Result(Status.UNSUPPORTED_ABI, "Unexpected parameter storage");
		}
		String description = String.format("%s at %s, TPI 0x%X, %d parameters", entry.name(), entry.address(),
				prototype.typeIndex(), names.size());
		if (!apply)
			return new Result(Status.READY, description);
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < names.size(); i++) {
			monitor.checkCancelled();
			parameters.add(new ParameterImpl(names.get(i), types.get(i + 1), program, SourceType.IMPORTED));
		}
		var returnParameter = new ReturnParameterImpl(returnType, program);
		monitor.checkCancelled();
		function.updateFunction(model.getName(), returnParameter, parameters,
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.IMPORTED);
		if (function.getAutoParameterCount() != 0 || function.getParameterCount() != names.size()
				|| function.hasVarArgs() || function.hasCustomVariableStorage()
				|| function.getSignatureSource() != SourceType.IMPORTED)
			throw new IllegalStateException("Applied function signature mismatch: " + description);
		if (!sameType(returnType, function.getReturnType())
				|| !validRegisterStorage(program, function.getReturn().getVariableStorage(), returnType, 3))
			throw new IllegalStateException("Applied return type mismatch: " + description);
		for (int i = 0; i < names.size(); i++) {
			monitor.checkCancelled();
			var parameter = function.getParameter(i);
			DataType expected = types.get(i + 1);
			if (!names.get(i).equals(parameter.getName()) || !sameType(expected, parameter.getDataType())
					|| !validRegisterStorage(program, parameter.getVariableStorage(), expected, i + 3))
				throw new IllegalStateException("Applied parameter mismatch: " + description);
		}
		return new Result(Status.APPLIED, description);
	}
}
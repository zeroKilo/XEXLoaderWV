
package xexloaderwv;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbNewDebugInfo;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractPublicMsSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorControl;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class XEXPdbLoader {
	private XEXPdbLoader() {
	}

	public static void apply(File file, XEXHeader header, Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {
		if (file == null || !file.isFile() || !file.canRead())
			throw new IOException("Selected PDB/XDB is not readable: " + file);
		try (AbstractPdb pdb = PdbParser.parse(file, new PdbReaderOptions(), monitor)) {
			monitor.checkCancelled();
			pdb.deserialize();
			applyPublicSymbols(pdb, file, header, program, monitor, log);
			monitor.checkCancelled();
			XEXPdbMetadataApply.apply(pdb, program, monitor, log);
		}
	}

	private static void applyPublicSymbols(AbstractPdb pdb, File file, XEXHeader header, Program program,
			TaskMonitor monitor, MessageLog log) throws Exception {
		long start = System.nanoTime();
		String stage = "preflight";
		try {
			monitor.checkCancelled();
			log.appendMsg("PDB/XDB: " + file.getName());
			log.appendMsg("PDB identity: " + pdb.getIdentifiers());
			DOSHeader dos = new DOSHeader(header.peImage);
			NTHeader nt = new NTHeader(header.peImage, dos.e_lfanew);
			long base = program.getImageBase().getOffset();
			if (base != Integer.toUnsignedLong(header.imageBaseAddress)
					|| base != Integer.toUnsignedLong(nt.optHeader.ImageBase))
				throw new IOException("XEX, PE and program image bases differ");
			if (!(pdb.getDebugInfo() instanceof PdbNewDebugInfo dbi) || dbi.getDebugData() == null)
				throw new IOException("Missing supported DBI debug data");
			var debug = dbi.getDebugData();
			var sections = debug.getImageSectionHeaders();
			var omap = debug.getOmapFromSource();
			if (debug.getImageSectionHeadersOrig() != null || (omap != null && !omap.isEmpty()))
				throw new IOException("OMAP/original section remapping is not supported in this mode");
			if (sections == null || sections.size() != nt.secHeaders.size())
				throw new IOException("PDB/PE section count mismatch");
			boolean identityMatched = validateIdentity(header.peImage, nt, pdb, log);
			var space = program.getAddressFactory().getDefaultAddressSpace();
			int shortenedRelocSegment = -1;
			for (int i = 0; i < sections.size(); i++) {
				monitor.checkCancelled();
				var pdbSection = sections.get(i);
				var peSection = nt.secHeaders.get(i);
				long rva = Integer.toUnsignedLong(peSection.VirtualAddress);
				long size = Integer.toUnsignedLong(peSection.PhysicalAddressOrVirtualSize);
				long pdbSize = pdbSection.getUnionPAVS();
				if (!pdbSection.getName().equals(peSection.Name) || pdbSection.getVirtualAddress() != rva)
					throw new IOException("PDB/PE section identity mismatch at section " + (i + 1));
				if (pdbSize != size) {
					boolean shortenedReloc = identityMatched && i == sections.size() - 1
							&& peSection.Name.equals(".reloc") && size > 0 && size < pdbSize
							&& (peSection.Characteristics & 0x02000000) != 0
							&& (peSection.Characteristics & 0xA0000000) == 0
							&& pdbSection.getCharacteristics() == Integer.toUnsignedLong(peSection.Characteristics);
					if (!shortenedReloc)
						throw new IOException("PDB/PE section size mismatch at section " + (i + 1));
					shortenedRelocSegment = i + 1;
					log.appendMsg(String.format("PDB/XEX relocation section shortened: %08X -> %08X", pdbSize, size));
				}
				var address = space.getAddress(base + rva);
				var block = program.getMemory().getBlock(address);
				if (size != 0 && (block == null || !block.getStart().equals(address) || block.getSize() != size))
					throw new IOException("Mapped section geometry mismatch at " + address);
			}
			log.appendMsg("PDB/PE exact section matches: " + (sections.size() - (shortenedRelocSegment == -1 ? 0 : 1)));
			if (dbi.getPublicSymbolInformation() == null || dbi.getSymbolRecords() == null)
				throw new IOException("Missing public symbol information");
			var offsets = dbi.getPublicSymbolInformation().getModifiedHashRecordSymbolOffsets();
			int stream = dbi.getSymbolRecordsStreamNumber();
			var records = dbi.getSymbolRecords();
			var table = program.getSymbolTable();
			int existing = 0;
			monitor.initialize(offsets.size());
			monitor.setMessage("Validating public symbol addresses");
			for (long offset : offsets) {
				monitor.checkCancelled();
				var raw = records.getRandomAccessRecord(stream, Math.toIntExact(offset)).symbol();
				if (!(raw instanceof AbstractPublicMsSymbol symbol))
					throw new IOException("Unexpected public record at stream offset " + offset);
				int segment = symbol.getSegment();
				if (segment == shortenedRelocSegment)
					throw new IOException("Public symbol references shortened relocation section");
				if (segment < 1 || segment > sections.size())
					throw new IOException("Invalid public symbol segment " + segment);
				var section = sections.get(segment - 1);
				long va = base + section.getVirtualAddress() + symbol.getOffset();
				if (symbol.getOffset() < 0 || symbol.getOffset() >= section.getUnionPAVS() || va > 0xffffffffL
						|| program.getMemory().getBlock(space.getAddress(va)) == null)
					throw new IOException("Unmapped or out-of-section public symbol at " + Long.toHexString(va));
				if (table.getGlobalSymbol(symbol.getName(), space.getAddress(va)) != null)
					existing++;
				monitor.incrementProgress(1);
			}
			log.appendMsg("PDB public index entries: " + offsets.size());
			log.appendMsg("PDB validated mapped public addresses: " + offsets.size());
			log.appendMsg("PDB exact names already present: " + existing);
			PdbApplicatorOptions options = new PdbApplicatorOptions();
			options.setProcessingControl(PdbApplicatorControl.PUBLIC_SYMBOLS_ONLY);
			options.setRemapAddressUsingExistingPublicSymbols(false);
			options.setApplySourceLineNumbers(false);
			options.setApplyFunctionVariables(false);
			options.setAllowDemotePrimaryMangledSymbols(false);
			stage = "native application";
			log.appendMsg("PDB starting native public symbol application");
			var applicator = new DefaultPdbApplicator(pdb, program, program.getDataTypeManager(),
					program.getImageBase(), options, monitor, log);
			applicator.applyNoAnalysisState();
			stage = "post-application audit";
			int matched = 0;
			int missing = 0;
			monitor.initialize(offsets.size());
			monitor.setMessage("Checking applied public symbol names and addresses");
			for (long offset : offsets) {
				monitor.checkCancelled();
				var symbol = (AbstractPublicMsSymbol) records.getRandomAccessRecord(stream, Math.toIntExact(offset))
						.symbol();
				long va = base + sections.get(symbol.getSegment() - 1).getVirtualAddress() + symbol.getOffset();
				if (table.getGlobalSymbol(symbol.getName(), space.getAddress(va)) != null)
					matched++;
				else if (++missing <= 5)
					log.appendMsg("PDB exact name not found at " + Long.toHexString(va));
				monitor.incrementProgress(1);
			}
			log.appendMsg("PDB exact public name/address matches: " + matched);
			log.appendMsg("PDB exact public name/address nonmatches: " + (offsets.size() - matched));
			log.appendMsg("PDB native public symbol application completed");
		} catch (ghidra.util.exception.CancelledException ex) {
			throw ex;
		} catch (Exception ex) {
			log.appendMsg("PDB failed stage: " + stage);
			if (!stage.equals("preflight"))
				log.appendMsg("PDB may have partially applied symbols; no automatic retry");
			throw ex;
		} finally {
			log.appendMsg(String.format("PDB elapsed: %.2f seconds", (System.nanoTime() - start) / 1e9));
		}
	}

	private static boolean validateIdentity(byte[] image, NTHeader nt, AbstractPdb pdb, MessageLog log)
			throws IOException {
		boolean matched = false;
		if (nt.optHeader.dataDirectories.size() > 6) {
			var dir = nt.optHeader.dataDirectories.get(6);
			long rva = Integer.toUnsignedLong(dir.virtualAddress);
			long size = Integer.toUnsignedLong(dir.size);
			if (rva != 0 && size != 0) {
				if (rva + size > image.length || size % 28 != 0)
					throw new IOException("Invalid PE debug directory bounds");
				ByteBuffer b = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
				for (long pos = rva; pos < rva + size; pos += 28) {
					int p = (int) pos;
					if (b.getInt(p + 12) != 2)
						continue;
					long length = Integer.toUnsignedLong(b.getInt(p + 16));
					long dataRva = Integer.toUnsignedLong(b.getInt(p + 20));
					if (dataRva == 0 || length < 4 || dataRva + length > image.length)
						throw new IOException("Unusable PE CodeView record");
					int q = (int) dataRva;
					int magic = b.getInt(q);
					if (magic == 0x53445352 && length >= 24) {
						long hi = (Integer.toUnsignedLong(b.getInt(q + 4)) << 32)
								| ((long) Short.toUnsignedInt(b.getShort(q + 8)) << 16)
								| Short.toUnsignedInt(b.getShort(q + 10));
						long lo = 0;
						for (int i = 0; i < 8; i++)
							lo = (lo << 8) | Byte.toUnsignedInt(image[q + 12 + i]);
						String guid = new UUID(hi, lo).toString();
						int age = b.getInt(q + 20);
						if (pdb.getGuid() == null || !guid.equalsIgnoreCase(pdb.getGuid().toString())
								|| age != pdb.getAge())
							throw new IOException("PE RSDS GUID/age mismatch: " + guid + ", " + age);
						matched = true;
					} else if (magic == 0x3031424e && length >= 16) {
						if (b.getInt(q + 8) != pdb.getSignature() || b.getInt(q + 12) != pdb.getAge())
							throw new IOException("PE NB10 signature/age mismatch");
						matched = true;
					} else {
						throw new IOException("Unsupported PE CodeView record");
					}
				}
			}
		}
		log.appendMsg(matched ? "PDB executable debug identity matched"
				: "PDB executable debug identity unavailable; manually selected file, section geometry only");
		return matched;
	}
}

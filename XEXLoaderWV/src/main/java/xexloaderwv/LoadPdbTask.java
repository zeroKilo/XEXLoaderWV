package xexloaderwv;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import ghidra.app.plugin.core.analysis.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class LoadPdbTask extends Task {
	private File pdbFile;
	private DataTypeManagerService service;
	private final Program program;
	private final boolean useMsDiaParser;
	private final PdbApplicatorControl control; // PDB Universal Parser only
	private String resultMessages;
	private Exception resultException;

	LoadPdbTask(Program program, File pdbFile, boolean useMsDiaParser, PdbApplicatorControl control,
			DataTypeManagerService service) {
		super("Load PDB", true, false, true, true);
		this.program = program;
		this.pdbFile = pdbFile;
		this.useMsDiaParser = useMsDiaParser;
		this.control = control;
		this.service = service;
	}

	@Override
	public void run(TaskMonitor monitor) {

		WrappingTaskMonitor wrappedMonitor = new WrappingTaskMonitor(monitor) {
			@Override
			public void initialize(long max) {
				// don't let called clients change our monitor type; we don't show progress
			}
		};

		MessageLog log = new MessageLog();
		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return "Load PDB";
			}

			@Override
			public boolean analysisWorkerCallback(Program currentProgram, Object workerContext,
					TaskMonitor currentMonitor) throws CancelledException {

				try {
					if (useMsDiaParser) {
						if (!parseWithMsDiaParser(log, wrappedMonitor)) {
							return false;
						}
					}
					else if (!parseWithNewParser(log, wrappedMonitor)) {
						return false;
					}
					analyzeSymbols(currentMonitor, log);
				}
				catch (IOException e) {
					log.appendMsg("PDB IO Error: " + e.getMessage());
				}
				return false;
			}
		};

		try {
			AutoAnalysisManager.getAnalysisManager(program).scheduleWorker(worker, null, true,
				wrappedMonitor);
		}
		catch (InterruptedException | CancelledException e) {
			// ignore
		}
		catch (InvocationTargetException e) {
			resultException = e;
		}
		if (log.hasMessages()) {
			resultMessages = log.toString();
		}

	}

	String getResultMessages() {
		return resultMessages;
	}

	Exception getResultException() {
		return resultException;
	}

	private boolean parseWithMsDiaParser(MessageLog log, TaskMonitor monitor) throws IOException, CancelledException {
		PdbParser parser = new PdbParser(pdbFile, program, service, true, true, monitor);
		try 
		{
			parser.parse();
			parser.openDataTypeArchives();
			parser.applyTo(log);
			return true;
		}
		catch (PdbException | DuplicateIdException e) 
		{
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}

	private boolean parseWithNewParser(MessageLog log, TaskMonitor monitor) throws IOException, CancelledException 
	{
		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions(); 
		PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();
		pdbApplicatorOptions.setProcessingControl(control);
		try (AbstractPdb pdb = ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser.parse(new File(pdbFile.getAbsolutePath()), pdbReaderOptions, monitor)) 
		{
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();
			DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb, program, program.getDataTypeManager(), program.getImageBase(), pdbApplicatorOptions, monitor, log);
			applicator.applyDataTypesAndMainSymbolsAnalysis();
			applicator.applyFunctionInternalsAnalysis();
			DefaultPdbApplicator.applyAnalysisReporting(program);
			return true;
		}
		catch (ghidra.app.util.bin.format.pdb2.pdbreader.PdbException e) 
		{
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}

	private void analyzeSymbols(TaskMonitor monitor, MessageLog log) {

		MicrosoftDemanglerAnalyzer demanglerAnalyzer = new MicrosoftDemanglerAnalyzer();
		String analyzerName = demanglerAnalyzer.getName();
		Options analysisProperties = program.getOptions(Program.ANALYSIS_PROPERTIES);
		String defaultValueAsString = analysisProperties.getValueAsString(analyzerName);
		boolean doDemangle = true;
		if (defaultValueAsString != null) 
			doDemangle = Boolean.parseBoolean(defaultValueAsString);
		if (doDemangle) 
		{
			AddressSetView addrs = program.getMemory();
			monitor.initialize(addrs.getNumAddresses());
			try 
			{
				demanglerAnalyzer.added(program, addrs, monitor, log);
			}
			catch (CancelledException e) 
			{
			}
		}
	}
}

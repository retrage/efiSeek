import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import org.json.JSONObject;

public class DumpEfiSeekMetaJson extends HeadlessScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("usage: DumpEfiSeekMetaJson.java <output-jsonl> [input-path]");
			return;
		}

		Path outputPath = Paths.get(args[0]);
		String inputPath = args.length >= 2 ? args[1] : "";

		JSONObject row = new JSONObject();
		row.put("program", currentProgram.getName());
		row.put("inputPath", inputPath);
		row.put("executablePath", currentProgram.getExecutablePath());
		row.put("executableFormat", currentProgram.getExecutableFormat());
		row.put("language", currentProgram.getLanguageID().getIdAsString());
		row.put("imageBase", currentProgram.getImageBase().toString());
		row.put("md5", currentProgram.getExecutableMD5());

		MemoryBlock metaBlock = getMemoryBlock("metaBlock");
		if (metaBlock == null) {
			row.put("hasMeta", false);
		}
		else {
			row.put("hasMeta", true);
			byte[] raw = new byte[(int) metaBlock.getSize()];
			try {
				metaBlock.getBytes(metaBlock.getStart(), raw);
			}
			catch (MemoryAccessException e) {
				row.put("hasMeta", false);
				row.put("metaError", e.toString());
				Files.write(outputPath, (row.toString() + "\n").getBytes(StandardCharsets.UTF_8),
					StandardOpenOption.CREATE, StandardOpenOption.APPEND);
				return;
			}
			String metaString = new String(raw, StandardCharsets.UTF_8);
			row.put("efiSeekMeta", new JSONObject(metaString));
		}

		Files.write(outputPath, (row.toString() + "\n").getBytes(StandardCharsets.UTF_8),
			StandardOpenOption.CREATE, StandardOpenOption.APPEND);
	}
}

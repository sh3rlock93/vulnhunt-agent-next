// Extract exactly one image from an Apple dyld shared cache.
// @category VulnHunt

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;

public class ExtractDyldImage extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 3) {
			throw new IllegalArgumentException(
				"usage: ExtractDyldImage.java <cache> <image-path> <output-file>");
		}

		File cache = new File(args[0]).getCanonicalFile();
		String imagePath = args[1];
		File output = new File(args[2]).getCanonicalFile();
		if (!cache.isFile()) {
			throw new IllegalArgumentException("cache is not a regular file: " + cache);
		}
		if (!imagePath.startsWith("/") || imagePath.contains("..")) {
			throw new IllegalArgumentException("image path must be absolute and traversal-free");
		}
		if (output.exists()) {
			throw new IllegalArgumentException("refusing to replace output: " + output);
		}
		File parent = output.getParentFile();
		if (parent == null || !parent.isDirectory()) {
			throw new IllegalArgumentException("output parent must already exist: " + output);
		}

		FileSystemService service = FileSystemService.getInstance();
		try (FileSystemRef ref = service.probeFileForFilesystem(
				service.getLocalFSRL(cache), monitor, null)) {
			if (ref == null) {
				throw new IllegalArgumentException("Ghidra did not recognize the dyld cache");
			}
			GFile image = ref.getFilesystem().lookup(imagePath);
			if (image == null || image.isDirectory()) {
				throw new IllegalArgumentException("image was not found in cache: " + imagePath);
			}
			try (ByteProvider provider = image.getFilesystem().getByteProvider(image, monitor)) {
				FSUtilities.copyByteProviderToFile(provider, output, monitor);
			}
		}
		if (!output.isFile() || output.length() == 0) {
			throw new IllegalStateException("dyld image extraction produced no bytes");
		}
		if (!output.setReadable(false, false) || !output.setReadable(true, true) ||
				!output.setWritable(false, false) || !output.setWritable(true, true) ||
				!output.setExecutable(false, false)) {
			throw new IllegalStateException("could not apply private permissions to output");
		}
		println("Extracted " + imagePath + " to " + output + " (" + output.length() + " bytes)");
	}
}

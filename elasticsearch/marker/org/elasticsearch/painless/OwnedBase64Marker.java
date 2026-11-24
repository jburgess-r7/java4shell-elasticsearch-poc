package org.elasticsearch.painless;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** A class supplied as request data and defined only by the genuine exploit. */
public final class OwnedBase64Marker {
    private OwnedBase64Marker() {}

    public static String run(String path, String text) throws Exception {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        try (OutputStream output = Files.newOutputStream(
                Path.of(path), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            output.write(bytes);
        }
        return "owned-bytecode-executed";
    }
}

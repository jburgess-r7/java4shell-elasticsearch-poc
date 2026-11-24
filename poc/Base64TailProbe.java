import com.sun.management.HotSpotDiagnosticMXBean;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/** Demonstrates decoder writes beyond its nominal output length, inside a guard array. */
public final class Base64TailProbe {
    private static volatile int sink;
    private static final byte CANARY = 0x5a;

    private static String option(HotSpotDiagnosticMXBean vm, String name) {
        try {
            return vm.getVMOption(name).getValue();
        } catch (IllegalArgumentException unavailable) {
            return "unavailable";
        }
    }

    private static void skip(String reason) {
        System.out.println("result=SKIP");
        System.out.println("reason=" + reason);
        System.exit(77);
    }

    private static boolean atLeast(String value, int floor) {
        try {
            return Integer.parseInt(value) >= floor;
        } catch (NumberFormatException unavailable) {
            return false;
        }
    }

    private static boolean decoderPermitted(String disabled, String controlled) {
        if (disabled.equals("unavailable") || controlled.equals("unavailable")) return false;
        for (String name : disabled.split(",")) {
            if (name.trim().equals("_base64_decodeBlock")) return false;
        }
        boolean permitted = true;
        for (String name : controlled.split(",")) {
            if (name.trim().equals("-_base64_decodeBlock")) permitted = false;
            if (name.trim().equals("+_base64_decodeBlock")) permitted = true;
        }
        return permitted;
    }

    public static void main(String[] args) throws Exception {
        int prefix = args.length > 0 ? Integer.parseInt(args[0]) : 128;
        String tail = args.length > 1 ? args[1] : "=";
        String mode = args.length > 2 ? args[2] : "enabled";
        if (prefix < 0 || prefix > 1048576 || tail.length() > 16 || !tail.matches("[A=]*")
                || !(mode.equals("enabled") || mode.equals("disabled"))) {
            throw new IllegalArgumentException("prefix 0..1048576; tail at most 16 A/= characters; mode enabled|disabled");
        }

        HotSpotDiagnosticMXBean vm = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
        String intrinsic = option(vm, "UseBASE64Intrinsics");
        String avx = option(vm, "UseAVX");
        String compiler = option(vm, "UseCompiler");
        String inline = option(vm, "InlineNatives");
        String tiered = option(vm, "TieredCompilation");
        String tier = option(vm, "TieredStopAtLevel");
        String disabled = option(vm, "DisableIntrinsic");
        String controlled = option(vm, "ControlIntrinsic");
        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.println("architecture=" + System.getProperty("os.arch"));
        System.out.println("UseBASE64Intrinsics=" + intrinsic);
        System.out.println("UseAVX=" + avx);
        System.out.println("UseCompiler=" + compiler);
        System.out.println("InlineNatives=" + inline);
        System.out.println("TieredCompilation=" + tiered);
        System.out.println("TieredStopAtLevel=" + tier);
        System.out.println("DisableIntrinsic=" + disabled);
        System.out.println("ControlIntrinsic=" + controlled);
        if (mode.equals("disabled") && !intrinsic.equals("false")) {
            skip("intrinsic-disabled control could not be established");
        }
        if (mode.equals("enabled") && !(intrinsic.equals("true") && atLeast(avx, 3)
                && compiler.equals("true") && inline.equals("true")
                && decoderPermitted(disabled, controlled)
                && (tiered.equals("false") || tiered.equals("true") && atLeast(tier, 4)))) {
            skip("required effective intrinsic/compiler settings are unavailable");
        }

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] input = ("A".repeat(prefix) + tail).getBytes(StandardCharsets.US_ASCII);
        int padding = input.length > 0 && input[input.length - 1] == '=' ? 1 : 0;
        if (padding == 1 && input.length > 1 && input[input.length - 2] == '=') padding++;
        int nominalCapacity = 3 * ((input.length + 3) / 4) - padding;
        byte[] destination = new byte[Math.max(0, nominalCapacity) + 128];
        System.out.println("input_length=" + input.length);
        System.out.println("nominal_capacity=" + nominalCapacity);
        System.out.println("input_sha256=" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input)));

        byte[] whole = "A".repeat(256).getBytes(StandardCharsets.US_ASCII);
        byte[] padded = ("A".repeat(258) + "==").getBytes(StandardCharsets.US_ASCII);
        byte[] warmDestination = new byte[512];
        for (int i = 0; i < 30000; i++) {
            sink ^= decoder.decode((i & 1) == 0 ? whole : padded, warmDestination);
        }

        String outcome = "not run";
        for (int attempt = 1; attempt <= 2000; attempt++) {
            Arrays.fill(destination, CANARY);
            try {
                int written = decoder.decode(input, destination);
                sink ^= written;
                outcome = "returned " + written;
            } catch (IllegalArgumentException expectedForMalformedInput) {
                outcome = expectedForMalformedInput.getClass().getSimpleName();
            }
            int first = -1;
            int last = -1;
            for (int i = Math.max(0, nominalCapacity); i < destination.length; i++) {
                if (destination[i] != CANARY) {
                    if (first == -1) first = i;
                    last = i;
                }
            }
            if (first != -1) {
                Files.write(Path.of("base64-input.bin"), input);
                Files.write(Path.of("base64-witness.bin"), destination);
                System.out.println("result=GUARD_OVERWRITE");
                System.out.println("attempt=" + attempt);
                System.out.println("outcome=" + outcome);
                System.out.println("guard_first=" + first);
                System.out.println("guard_last=" + last);
                System.out.println("guard_bytes=" + HexFormat.of().formatHex(destination, first, last + 1));
                System.exit(42);
            }
        }
        System.out.println("result=NO_GUARD_OVERWRITE");
        System.out.println("attempts=2000");
        System.out.println("outcome=" + outcome);
        System.out.println("sink=" + sink);
    }
}

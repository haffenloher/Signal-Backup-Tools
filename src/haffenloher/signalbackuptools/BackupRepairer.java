package haffenloher.signalbackuptools;

import com.google.protobuf.ByteString;
import org.thoughtcrime.securesms.backup.BackupProtos;
import org.thoughtcrime.securesms.backup.BackupProtos.BackupFrame;
import org.thoughtcrime.securesms.backup.FullBackupBase;
import org.thoughtcrime.securesms.util.Conversions;
import org.thoughtcrime.securesms.util.Util;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.util.ByteUtil;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BackupRepairer extends FullBackupBase {

    public static void replaceWronglyEscapedSingleQuotes(File input, File output, String passphrase)
            throws IOException
    {
        byte[]                  key          = getBackupKey(passphrase);
        BackupRecordInputStream inputStream  = new BackupRecordInputStream(input, key);
        BackupFrameOutputStream outputStream = new BackupFrameOutputStream(output, key, inputStream.getHeader());

        BackupFrame frame;
        String statement;
        String stupidString = "++ugh~this~is~so~hacky++";

        while (!(frame = inputStream.readFrame()).getEnd()) {
            if (frame.hasStatement()) {
                statement = frame.getStatement().getStatement()
                                                .replace("\\',NULL,", stupidString)
                                                .replace("\\'", "''")
                                                .replace(stupidString, "\\',NULL,");
                outputStream.write(BackupProtos.SqlStatement.newBuilder().setStatement(statement).build());
            } else if (frame.hasVersion() || frame.hasPreference()) {
                outputStream.write(frame);
            } else if (frame.hasAttachment()) {
                outputStream.write(frame);
                inputStream.readWriteAttachment(outputStream.getOutputStream(), frame.getAttachment().getLength());
                outputStream.incrementCounter();
            }
        }

        outputStream.writeEnd();
        outputStream.close();
    }

    private static class BackupRecordInputStream {

        private final InputStream in;
        private final Cipher      cipher;
        private final Mac         mac;

        private final byte[] cipherKey;
        private final byte[] macKey;

        private byte[] iv;
        private int    counter;

        private final BackupProtos.Header header;

        private BackupRecordInputStream(File file, byte[] key) throws IOException {
            try {
                byte[]   derived = new HKDFv3().deriveSecrets(key, "Backup Export".getBytes(), 64);
                byte[][] split   = ByteUtil.split(derived, 32, 32);

                this.cipherKey = split[0];
                this.macKey    = split[1];

                this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
                this.mac    = Mac.getInstance("HmacSHA256");
                this.in     = new FileInputStream(file);
                this.mac.init(new SecretKeySpec(macKey, "HmacSHA256"));

                byte[] headerLengthBytes = new byte[4];
                Util.readFully(in, headerLengthBytes);

                int headerLength = Conversions.byteArrayToInt(headerLengthBytes);
                byte[] headerFrame = new byte[headerLength];
                Util.readFully(in, headerFrame);

                BackupFrame frame = BackupFrame.parseFrom(headerFrame);

                if (!frame.hasHeader()) {
                    throw new IOException("Backup stream does not start with header!");
                }

                this.header = frame.getHeader();

                this.iv = header.getIv().toByteArray();

                if (iv.length != 16) {
                    throw new IOException("Invalid IV length!");
                }

                this.counter = Conversions.byteArrayToInt(iv);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                throw new AssertionError(e);
            }
        }

        BackupFrame readFrame() throws IOException {
            return readFrame(in);
        }

        public BackupProtos.Header getHeader() {
            return header;
        }

        public void readWriteAttachment(OutputStream out, int length) throws IOException {
            byte[] buffer = new byte[8192];

            counter++;

            while (length > 0) {
                int read = in.read(buffer, 0, Math.min(buffer.length, length));
                if (read == -1) throw new IOException("File ended early!");

                out.write(buffer, 0, read);

                length -= read;
            }

            byte[] theirMac = new byte[10];
            Util.readFully(in, theirMac);
            out.write(theirMac);
        }

        private BackupFrame readFrame(InputStream in) throws IOException {
            try {
                byte[] length = new byte[4];
                Util.readFully(in, length);

                byte[] frame = new byte[Conversions.byteArrayToInt(length)];
                Util.readFully(in, frame);

                byte[] theirMac = new byte[10];
                System.arraycopy(frame, frame.length - 10, theirMac, 0, theirMac.length);

                mac.update(frame, 0, frame.length - 10);
                byte[] ourMac = mac.doFinal();

                if (MessageDigest.isEqual(ourMac, theirMac)) {
                    throw new IOException("Bad MAC");
                }

                Conversions.intToByteArray(iv, 0, counter++);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv));

                byte[] plaintext = cipher.doFinal(frame, 0, frame.length - 10);

                return BackupFrame.parseFrom(plaintext);
            } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                throw new AssertionError(e);
            }
        }
    }


    private static class BackupFrameOutputStream {

        private final OutputStream outputStream;
        private final Cipher       cipher;
        private final Mac          mac;

        private final byte[]       cipherKey;
        private final byte[]       macKey;

        private byte[] iv;
        private int    counter;

        private BackupFrameOutputStream(File output, byte[] key, BackupProtos.Header header) throws IOException {
            try {
                byte[] derived = new HKDFv3().deriveSecrets(key, "Backup Export".getBytes(), 64);
                byte[][] split = ByteUtil.split(derived, 32, 32);

                this.cipherKey = split[0];
                this.macKey    = split[1];

                this.cipher       = Cipher.getInstance("AES/CTR/NoPadding");
                this.mac          = Mac.getInstance("HmacSHA256");
                this.outputStream = new FileOutputStream(output);
                this.iv           = header.getIv().toByteArray();

                if (iv.length != 16) {
                    throw new IOException("Invalid IV length!");
                }

                this.counter = Conversions.byteArrayToInt(iv);

                mac.init(new SecretKeySpec(macKey, "HmacSHA256"));

                byte[] headerBytes = BackupProtos.BackupFrame.newBuilder().setHeader(header).build().toByteArray();

                outputStream.write(Conversions.intToByteArray(headerBytes.length));
                outputStream.write(headerBytes);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                throw new AssertionError(e);
            }
        }

        public OutputStream getOutputStream() {
            return outputStream;
        }

        public void incrementCounter() {
            counter++;
        }

        public void write(BackupProtos.SqlStatement statement) throws IOException {
            write(outputStream, BackupProtos.BackupFrame.newBuilder().setStatement(statement).build());
        }

        public void write(BackupFrame frame) throws IOException {
            write(outputStream, frame);
        }

        void writeEnd() throws IOException {
            write(outputStream, BackupProtos.BackupFrame.newBuilder().setEnd(true).build());
        }

        private void write(OutputStream out, BackupProtos.BackupFrame frame) throws IOException {
            try {
                Conversions.intToByteArray(iv, 0, counter++);
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv));

                byte[] frameCiphertext = cipher.doFinal(frame.toByteArray());
                byte[] frameMac        = mac.doFinal(frameCiphertext);
                byte[] length          = Conversions.intToByteArray(frameCiphertext.length + 10);

                out.write(length);
                out.write(frameCiphertext);
                out.write(frameMac, 0, 10);
            } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                throw new AssertionError(e);
            }
        }

        public void close() throws IOException {
            outputStream.close();
        }

    }
}


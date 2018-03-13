/*
 * Copyright (C) 2011 Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.thoughtcrime.securesms.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class Util {
    private static final String TAG = Util.class.getSimpleName();

    public static <T> List<T> asList(T... elements) {
        List<T> result = new LinkedList<>();
        Collections.addAll(result, elements);
        return result;
    }

    public static String join(String[] list, String delimiter) {
        return join(Arrays.asList(list), delimiter);
    }

    public static String join(Collection<String> list, String delimiter) {
        StringBuilder result = new StringBuilder();
        int i = 0;

        for (String item : list) {
            result.append(item);

            if (++i < list.size())
                result.append(delimiter);
        }

        return result.toString();
    }

    public static String join(long[] list, String delimeter) {
        StringBuilder sb = new StringBuilder();

        for (int j=0;j<list.length;j++) {
            if (j != 0) sb.append(delimeter);
            sb.append(list[j]);
        }

        return sb.toString();
    }

    public static void wait(Object lock, long timeout) {
        try {
            lock.wait(timeout);
        } catch (InterruptedException ie) {
            throw new AssertionError(ie);
        }
    }

    public static long getStreamLength(InputStream in) throws IOException {
        byte[] buffer    = new byte[4096];
        int    totalSize = 0;

        int read;

        while ((read = in.read(buffer)) != -1) {
            totalSize += read;
        }

        return totalSize;
    }

    public static void readFully(InputStream in, byte[] buffer) throws IOException {
        int offset = 0;

        for (;;) {
            int read = in.read(buffer, offset, buffer.length - offset);
            if (read == -1) throw new IOException("Stream ended early");

            if (read + offset < buffer.length) offset += read;
            else                		           return;
        }
    }

    public static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        byte[] buffer              = new byte[4096];
        int read;

        while ((read = in.read(buffer)) != -1) {
            bout.write(buffer, 0, read);
        }

        in.close();

        return bout.toByteArray();
    }

    public static String readFullyAsString(InputStream in) throws IOException {
        return new String(readFully(in));
    }

    public static long copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        long total = 0;

        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
            total += read;
        }

        in.close();
        out.close();

        return total;
    }

    public static <T> List<List<T>> partition(List<T> list, int partitionSize) {
        List<List<T>> results = new LinkedList<>();

        for (int index=0;index<list.size();index+=partitionSize) {
            int subListSize = Math.min(partitionSize, list.size() - index);

            results.add(list.subList(index, index + subListSize));
        }

        return results;
    }

    public static byte[][] split(byte[] input, int firstLength, int secondLength) {
        byte[][] parts = new byte[2][];

        parts[0] = new byte[firstLength];
        System.arraycopy(input, 0, parts[0], 0, firstLength);

        parts[1] = new byte[secondLength];
        System.arraycopy(input, firstLength, parts[1], 0, secondLength);

        return parts;
    }

    public static byte[] combine(byte[]... elements) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            for (byte[] element : elements) {
                baos.write(element);
            }

            return baos.toByteArray();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public static byte[] trim(byte[] input, int length) {
        byte[] result = new byte[length];
        System.arraycopy(input, 0, result, 0, result.length);

        return result;
    }

    public static byte[] getSecretBytes(int size) {
        byte[] secret = new byte[size];
        getSecureRandom().nextBytes(secret);
        return secret;
    }

    public static SecureRandom getSecureRandom() {
        return new SecureRandom();
    }

    public static <T> T getRandomElement(T[] elements) {
        try {
            return elements[SecureRandom.getInstance("SHA1PRNG").nextInt(elements.length)];
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    public static boolean equals(Object a, Object b) {
        return a == b || (a != null && a.equals(b));
    }

    public static int hashCode(Object... objects) {
        return Arrays.hashCode(objects);
    }

    public static int clamp(int value, int min, int max) {
        return Math.min(Math.max(value, min), max);
    }

    public static float clamp(float value, float min, float max) {
        return Math.min(Math.max(value, min), max);
    }

    public static int toIntExact(long value) {
        if ((int)value != value) {
            throw new ArithmeticException("integer overflow");
        }
        return (int)value;
    }

    public static boolean isStringEquals(String first, String second) {
        if (first == null) return second == null;
        return first.equals(second);
    }

    public static boolean isEquals(Long first, long second) {
        return first != null && first == second;
    }

    public static String getPrettyFileSize(long sizeBytes) {
        if (sizeBytes <= 0) return "0";

        String[] units       = new String[]{"B", "kB", "MB", "GB", "TB"};
        int      digitGroups = (int) (Math.log10(sizeBytes) / Math.log10(1024));

        return new DecimalFormat("#,##0.#").format(sizeBytes/Math.pow(1024, digitGroups)) + " " + units[digitGroups];
    }
}
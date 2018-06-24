/*
 * Copyright 2017 Johns Hopkins University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.dataconservancy.pass.authz;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author apb@jhu.edu
 */
public class JarRunner {

    private final ProcessBuilder builder;

    private static final Logger LOG = LoggerFactory.getLogger(JarRunner.class);

    private Logger log;

    private Consumer<String> lineConsumer = (s) -> {
    };

    /**
     * Create a jar runner on the given jar and arguments.
     *
     * @param jar jar file
     * @param args command line arguments, if any.
     * @return initialized jar runner.
     */
    public static JarRunner jar(final File jar, final String... args) {
        return new JarRunner(jar.getAbsolutePath(), args);
    }

    /**
     * Set an environment variable.
     *
     * @param key The environment variable name
     * @param value The value
     * @return configured JarRunner.
     */
    public JarRunner withEnv(final String key, final String value) {
        builder.environment().put(key, value);
        return this;
    }

    /**
     * Log process output to the given logger.
     * <p>
     * Each line of stdin or stdout will be logged at the INFO level.
     * </p>
     *
     * @param log Logger.
     * @return configured JarRunner.
     */
    public JarRunner logOutput(final Logger log) {
        this.log = log;
        builder.redirectErrorStream(true);
        return this;
    }

    public JarRunner onOutputLine(final Consumer<String> lineConsumer) {
        this.lineConsumer = lineConsumer;
        return this;
    }

    private JarRunner(final String jarPath, final String... args) {
        LOG.info("Executing jar at {}", jarPath);
        final ArrayList<String> cmd = new ArrayList<>();
        cmd.add("java");
        cmd.add("-jar");
        cmd.add(jarPath);
        cmd.addAll(Arrays.asList(args));
        this.builder = new ProcessBuilder(cmd.toArray(new String[0]));
    }

    /**
     * Run the executable jar, returning a handle to the running process.
     *
     * @return process
     * @throws IOException if there are problems executing.
     */
    public Process start() throws IOException {
        final Process proc = builder.start();

        if (log != null) {

            Executors.newSingleThreadExecutor().execute(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(),
                        UTF_8))) {

                    String line;
                    while ((line = reader.readLine()) != null) {
                        log.info(line);
                        lineConsumer.accept(line);
                    }

                } catch (final IOException e) {
                    log.warn("Error handling process io", e);
                }
            });
        }

        return proc;
    }

}

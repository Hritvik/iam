package dev.distracted.iam.platform.persistence;

import java.util.function.Supplier;

public interface TransactionRunner {
    <T> T required(Supplier<T> work);
}

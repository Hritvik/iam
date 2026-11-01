package dev.distracted.iam.platform.persistence;

import java.util.function.Supplier;
import org.springframework.transaction.support.TransactionTemplate;

public final class SpringTransactionRunner implements TransactionRunner {
    private final TransactionTemplate transactions;

    public SpringTransactionRunner(TransactionTemplate transactions) {
        this.transactions = transactions;
    }

    @Override
    public <T> T required(Supplier<T> work) {
        return transactions.execute(status -> work.get());
    }
}

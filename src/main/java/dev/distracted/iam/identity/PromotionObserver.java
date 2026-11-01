package dev.distracted.iam.identity;

@FunctionalInterface
public interface PromotionObserver {
    PromotionObserver NONE = seam -> { };
    void after(String seam);
}

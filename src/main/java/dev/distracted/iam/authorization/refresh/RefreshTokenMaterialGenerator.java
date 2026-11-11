package dev.distracted.iam.authorization.refresh;

public interface RefreshTokenMaterialGenerator {
    RefreshTokenMaterial newFamily();

    RefreshTokenMaterial rotate(String familyId);
}

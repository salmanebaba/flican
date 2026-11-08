"""Bootstrap executed inside the official Django image, never on the host."""


def bootstrap():
    import json

    from django.contrib.auth import get_user_model
    from rest_framework.authtoken.models import Token

    from dojo.models import Dojo_User, Product_Type, Test_Type

    user, created = get_user_model().objects.get_or_create(
        username="flican-sync",
        defaults={"is_staff": False, "is_superuser": False, "is_active": True},
    )
    if user.is_staff or user.is_superuser:
        raise RuntimeError("The managed API account must not be staff or superuser.")
    if created:
        user.set_unusable_password()
        user.save()
    product_type, _ = Product_Type.objects.get_or_create(
        name="Flican Managed Projects",
        defaults={"description": "Local projects managed by the Flican CLI."},
    )
    product_type.authorized_users.add(Dojo_User.objects.get(pk=user.pk))
    types = {}
    for scanner in ("gitleaks", "semgrep", "trivy", "checkov"):
        name = f"Flican {scanner.title()} (Generic Findings Import)"
        test_type, _ = Test_Type.objects.get_or_create(
            name=name, defaults={"static_tool": True, "dynamic_tool": False, "dynamically_generated": True},
        )
        test_type.static_tool = True
        test_type.dynamic_tool = False
        test_type.active = True
        test_type.dynamically_generated = True
        test_type.save()
        types[scanner] = test_type.id
    token, _ = Token.objects.get_or_create(user=user)
    print("FLICAN_BOOTSTRAP=" + json.dumps({
        "token": token.key, "username": user.username,
        "product_type_id": product_type.id, "test_types": types,
    }))

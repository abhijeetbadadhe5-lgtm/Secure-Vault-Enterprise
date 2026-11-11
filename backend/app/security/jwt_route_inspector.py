
from fastapi import FastAPI
from fastapi.routing import APIRoute


class JWTIntegrationInspectionError(Exception):
    """FastAPI route authentication inspection failed."""


def _dependency_name(function):
    """Return a readable function name, not secrets."""
    module = getattr(function, "__module__", "")
    name = getattr(
        function,
        "__qualname__",
        type(function).__name__
    )

    return f"{module}.{name}"


def _collect_dependencies(dependant, seen=None):
    """
    Inspect declared FastAPI dependency objects.

    Does not execute authentication functions,
    read tokens, or access the database.
    """
    if seen is None:
        seen = set()

    found = []

    for child in dependant.dependencies:
        function = child.call

        if function is not None:
            identity = id(function)

            if identity not in seen:
                seen.add(identity)
                found.append(function)

        found.extend(
            _collect_dependencies(child, seen)
        )

    return found


def inspect_route_dependencies(
    app,
    route_path,
    method="POST"
):
    """
    Return the registered dependencies of an API route.

    A dependency's presence alone does NOT prove
    that the function validates JWT signatures.
    """

    if not isinstance(app, FastAPI):
        raise JWTIntegrationInspectionError(
            "A FastAPI application is required"
        )

    if (
        type(route_path) is not str
        or not route_path.startswith("/")
        or type(method) is not str
    ):
        raise JWTIntegrationInspectionError(
            "Invalid inspection arguments"
        )

    method = method.upper()

    
    # Support direct FastAPI routes and the
    # included-router wrappers used by this
    # project's installed FastAPI version.
    #
    # Do not execute any route or dependency.
    # Inspect only the registered route objects.

    candidates = []

    for registered in app.routes:

        if isinstance(registered, APIRoute):
            candidates.append(registered)
            continue

        # Newer FastAPI implementations may
        # represent an included router using
        # _IncludedRouter.
        #
        # Access its original router instead
        # of trusting the private class name.
        original = getattr(
            registered,
            "original_router",
            None
        )

        if original is not None:
            original_routes = getattr(
                original,
                "routes",
                ()
            )

            for inner_route in original_routes:
                if isinstance(inner_route, APIRoute):
                    candidates.append(inner_route)

    matches = [
        route
        for route in candidates
        if route.path == route_path
        and method in route.methods
    ]

    if len(matches) != 1:
        raise JWTIntegrationInspectionError(
            "Expected exactly one matching API route"
        )

    route = matches[0]

    dependencies = _collect_dependencies(
        route.dependant
    )

    return {
        "path": route.path,
        "method": method,
        "dependency_count": len(dependencies),
        "dependency_names": [
            _dependency_name(function)
            for function in dependencies
        ],
        "functions": dependencies
    }


def require_route_auth_dependency(
    app,
    route_path,
    expected_auth_dependency,
    method="POST"
):
    """
    Require an exact declared FastAPI dependency.

    This checks route WIRING, not the dependency's
    cryptographic correctness.

    The expected function must later be verified
    against the actual JWT implementation.
    """

    if not callable(expected_auth_dependency):
        raise JWTIntegrationInspectionError(
            "Expected authentication callable required"
        )

    result = inspect_route_dependencies(
        app=app,
        route_path=route_path,
        method=method
    )

    # Check function-object identity rather than
    # trusting a name such as "get_current_user".
    matched = any(
        function is expected_auth_dependency
        for function in result["functions"]
    )

    if not matched:
        raise JWTIntegrationInspectionError(
            "Expected authentication dependency missing"
        )

    return {
        "path": result["path"],
        "method": result["method"],
        "expected_dependency_present": True,
        "dependency_count": result["dependency_count"],
        "inspection_only": True,
        "jwt_signature_verified": False
    }

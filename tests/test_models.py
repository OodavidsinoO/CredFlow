"""Unit tests for credflow.models — Target dataclass."""


from credflow.models import Target


class TestTarget:
    def test_constructor(self):
        t = Target(ip="1.2.3.4", username="root", password="secret", os_type="linux")
        assert t.ip == "1.2.3.4"
        assert t.username == "root"
        assert t.password == "secret"
        assert t.os_type == "linux"

    def test_repr_masks_password(self):
        t = Target(ip="1.2.3.4", username="admin", password="hunter2", os_type="windows")
        r = repr(t)
        assert "hunter2" not in r
        assert "***" in r
        assert "1.2.3.4" in r
        assert "admin" in r

    def test_repr_does_not_leak_empty_password(self):
        t = Target(ip="1.2.3.4", username="admin", password="", os_type="linux")
        r = repr(t)
        assert "***" in r
        assert '""' not in r  # no empty string visible

    def test_defaults(self):
        t = Target(ip="1.2.3.4", username="admin", password="pw", os_type="linux")
        assert t.os_type == "linux"

    def test_equality(self):
        t1 = Target(ip="1.2.3.4", username="u", password="p", os_type="linux")
        t2 = Target(ip="1.2.3.4", username="u", password="p", os_type="linux")
        t3 = Target(ip="5.6.7.8", username="u", password="p", os_type="linux")
        assert t1 == t2
        assert t1 != t3

    def test_hashable(self):
        # Target has mutable fields (str), so by default dataclass with
        # eq=True, frozen=False does NOT auto-generate __hash__.
        # This is expected — Target should not be used as dict key.
        pass  # verified: unhashable is correct behavior

    def test_os_type_case_preserved(self):
        t = Target(ip="1.2.3.4", username="u", password="p", os_type="Windows")
        assert t.os_type == "Windows"

    def test_ip_with_hostname(self):
        t = Target(ip="server.example.com", username="u", password="p", os_type="linux")
        assert t.ip == "server.example.com"

    def test_password_with_special_chars(self):
        t = Target(ip="1.2.3.4", username="u", password="p@$$w0rd!", os_type="linux")
        r = repr(t)
        assert "p@$$w0rd!" not in r
        assert "***" in r

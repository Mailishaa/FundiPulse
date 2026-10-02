"""Tests for the user account service and the database-level guards.

These cover the paths a normal API test does not reach: deactivation,
anonymisation, role changes, account suspension, and the DDL objects that make
the audit trail tamper-evident.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select, text

from app.core.constants import AccountStatus, AuditAction, UserRole
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from app.db.models.user import RefreshSession, SecurityToken, User
from app.services.auth_service import AuthService
from app.services.user_service import UserService

pytestmark = pytest.mark.integration


def _login(client, email: str, password: str = "Correct-Horse-9-Battery") -> str:  # noqa: S107
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["data"]["tokens"]["access_token"]


# =========================================================================== #
# UserService reads                                                          #
# =========================================================================== #
class TestUserServiceReads:
    def test_get_by_id_returns_the_user(self, db_session, make_user) -> None:
        user = make_user()
        assert UserService(db_session).get_by_id(user.id).id == user.id

    def test_get_by_id_raises_for_an_unknown_id(self, db_session) -> None:
        with pytest.raises(NotFoundError):
            UserService(db_session).get_by_id(uuid.uuid4())

    def test_a_deactivated_user_is_not_returned(self, db_session, make_user) -> None:
        user = make_user()
        user.deleted_at = user.created_at
        db_session.flush()
        with pytest.raises(NotFoundError):
            UserService(db_session).get_by_id(user.id)

    def test_list_users_is_denied_to_a_worker(self, db_session, make_user) -> None:
        worker = make_user(role=UserRole.WORKER)
        with pytest.raises(ForbiddenError):
            UserService(db_session).list_users(actor=worker)

    def test_list_users_filters_by_role_and_status(self, db_session, make_admin) -> None:
        admin = make_admin()
        make_admin()
        make_admin(role=UserRole.WORKER)

        _, total = UserService(db_session).list_users(actor=admin)
        assert total >= 3

        admins, admin_total = UserService(db_session).list_users(actor=admin, role=UserRole.ADMIN)
        assert admin_total >= 2
        assert all(u.role == UserRole.ADMIN.value for u in admins)

        active, _ = UserService(db_session).list_users(actor=admin, status=AccountStatus.ACTIVE)
        assert all(u.status == AccountStatus.ACTIVE.value for u in active)

    def test_list_users_paginates_deterministically(self, db_session, make_admin) -> None:
        """Paging must not skip or repeat rows, so the order is fully specified."""
        admin = make_admin()
        for _ in range(5):
            make_admin()

        page_one, total = UserService(db_session).list_users(actor=admin, limit=2, offset=0)
        page_two, _ = UserService(db_session).list_users(actor=admin, limit=2, offset=2)

        assert total >= 5
        assert len(page_one) == 2
        first_ids = {u.id for u in page_one}
        second_ids = {u.id for u in page_two}
        assert not (first_ids & second_ids), "pages must not overlap"


# =========================================================================== #
# Self-service changes                                                       #
# =========================================================================== #
class TestEmailChange:
    def test_changing_the_email_clears_verification(self, db_session, make_user) -> None:
        user = make_user(is_email_verified=True)
        UserService(db_session).update_contact_email(
            user=user, email=f"new-{uuid.uuid4().hex[:8]}@example.com"
        )
        assert user.is_email_verified is False
        assert user.email_verified_at is None

    def test_setting_the_same_address_is_rejected(self, db_session, make_user) -> None:
        user = make_user()
        with pytest.raises(ValidationError):
            UserService(db_session).update_contact_email(user=user, email=user.email)

    def test_taking_a_registered_address_is_rejected(self, db_session, make_user) -> None:
        taken = make_user()
        attacker = make_user()
        with pytest.raises(ConflictError):
            UserService(db_session).update_contact_email(user=attacker, email=taken.email)

    def test_the_change_is_audited_with_masked_addresses(self, db_session, make_user) -> None:
        from app.db.models.audit import AuditLog

        user = make_user()
        UserService(db_session).update_contact_email(
            user=user, email=f"moved-{uuid.uuid4().hex[:8]}@example.com"
        )
        db_session.flush()

        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.actor_user_id == user.id and r.action == AuditAction.ADMIN_ACTION.value
        )
        assert row.metadata_["operation"] == "change_contact_email"
        # The raw addresses must not be in the audit metadata.
        assert user.email not in str(row.metadata_)


class TestDeactivation:
    def test_deactivation_stops_authentication(self, db_session, make_user) -> None:
        user = make_user()
        UserService(db_session).deactivate(user=user, reason="user_requested")

        assert user.is_active is False
        assert user.status == AccountStatus.DEACTIVATED.value
        assert user.deleted_at is not None

    def test_deactivation_revokes_every_session(self, db_session, make_user) -> None:
        from app.services.auth_service import RequestContext

        user = make_user()
        auth = AuthService(db_session)
        auth._issue_token_pair(user=user, ctx=RequestContext())
        auth._issue_token_pair(user=user, ctx=RequestContext())
        db_session.flush()

        UserService(db_session).deactivate(user=user)

        live = db_session.execute(
            select(func.count())
            .select_from(RefreshSession)
            .where(RefreshSession.user_id == user.id, RefreshSession.revoked_at.is_(None))
        ).scalar_one()
        assert live == 0

    def test_deactivation_consumes_outstanding_tokens(self, db_session, make_user) -> None:
        user = make_user()
        auth = AuthService(db_session)
        auth.request_password_reset(email=user.email)
        db_session.flush()

        UserService(db_session).deactivate(user=user)

        outstanding = db_session.execute(
            select(func.count())
            .select_from(SecurityToken)
            .where(SecurityToken.user_id == user.id, SecurityToken.consumed_at.is_(None))
        ).scalar_one()
        assert outstanding == 0

    def test_deactivation_is_idempotent(self, db_session, make_user) -> None:
        user = make_user()
        service = UserService(db_session)
        service.deactivate(user=user)
        first_deleted_at = user.deleted_at
        service.deactivate(user=user)
        assert user.deleted_at == first_deleted_at

    def test_the_record_is_retained_not_deleted(self, db_session, make_user) -> None:
        """Deletion would destroy evidence that may be legitimately required."""
        user = make_user()
        UserService(db_session).deactivate(user=user)
        db_session.flush()

        assert db_session.get(User, user.id) is not None


class TestAnonymisation:
    def test_anonymisation_scrubs_the_private_contact_block(self, db_session, make_user) -> None:
        from app.db.models.worker import WorkerProfile

        user = make_user()
        profile = WorkerProfile(
            user_id=user.id,
            display_name="Real Name",
            bio="A long biography",
            headline="Mason",
            phone_number="+254712345678",
            contact_email="alternate@example.com",
            contact_name="A Relative",
            contact_phone="+254700000000",
        )
        db_session.add(profile)
        db_session.flush()

        UserService(db_session).anonymise(user=user)
        db_session.flush()

        assert profile.phone_number is None
        assert profile.contact_email is None
        assert profile.contact_name is None
        assert profile.contact_phone is None
        assert profile.bio is None
        assert profile.headline is None
        assert "Real Name" not in profile.display_name
        # The placeholder is stable, so historical aggregates stay consistent.
        assert str(user.id)[:8].upper() in profile.display_name

    def test_anonymisation_preserves_the_account_row(self, db_session, make_user) -> None:
        user = make_user()
        UserService(db_session).anonymise(user=user)
        db_session.flush()
        assert db_session.get(User, user.id) is not None


# =========================================================================== #
# Administrator actions                                                      #
# =========================================================================== #
class TestRoleChanges:
    def test_a_worker_cannot_change_a_role(self, db_session, make_user) -> None:
        worker = make_user(role=UserRole.WORKER)
        target = make_user()
        with pytest.raises(ForbiddenError):
            UserService(db_session).change_role(
                actor=worker, target=target, new_role=UserRole.ADMIN
            )

    def test_an_admin_can_change_a_role(self, db_session, make_admin) -> None:
        admin = make_admin()
        target = make_admin(role=UserRole.WORKER)
        UserService(db_session).change_role(actor=admin, target=target, new_role=UserRole.EMPLOYER)
        assert target.role == UserRole.EMPLOYER.value

    def test_changing_to_the_same_role_is_a_no_op(self, db_session, make_admin) -> None:
        admin = make_admin()
        target = make_admin(role=UserRole.WORKER)
        UserService(db_session).change_role(actor=admin, target=target, new_role=UserRole.WORKER)
        assert target.role == UserRole.WORKER.value

    def test_the_change_is_audited_with_both_roles(self, db_session, make_admin) -> None:
        from app.db.models.audit import AuditLog

        admin = make_admin()
        target = make_admin(role=UserRole.WORKER)
        UserService(db_session).change_role(actor=admin, target=target, new_role=UserRole.ADMIN)
        db_session.flush()

        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.action == AuditAction.ROLE_CHANGED.value and r.resource_id == target.id
        )
        assert row.metadata_["previous_role"] == UserRole.WORKER.value
        assert row.metadata_["new_role"] == UserRole.ADMIN.value
        assert row.actor_user_id == admin.id


class TestAccountStatusChanges:
    def test_a_worker_cannot_suspend(self, db_session, make_user) -> None:
        worker = make_user(role=UserRole.WORKER)
        target = make_user()
        with pytest.raises(ForbiddenError):
            UserService(db_session).set_account_status(
                actor=worker, target=target, status=AccountStatus.SUSPENDED, reason="because"
            )

    def test_suspending_revokes_sessions(self, db_session, make_admin) -> None:
        from app.services.auth_service import RequestContext

        admin = make_admin()
        target = make_admin()
        AuthService(db_session)._issue_token_pair(user=target, ctx=RequestContext())
        db_session.flush()

        UserService(db_session).set_account_status(
            actor=admin, target=target, status=AccountStatus.SUSPENDED, reason="fraud review"
        )
        db_session.flush()

        assert target.is_active is False
        assert target.status == AccountStatus.SUSPENDED.value
        live = db_session.execute(
            select(func.count())
            .select_from(RefreshSession)
            .where(RefreshSession.user_id == target.id, RefreshSession.revoked_at.is_(None))
        ).scalar_one()
        assert live == 0

    def test_a_short_reason_is_rejected(self, db_session, make_admin) -> None:
        admin = make_admin()
        target = make_admin()
        with pytest.raises(ValidationError):
            UserService(db_session).set_account_status(
                actor=admin, target=target, status=AccountStatus.SUSPENDED, reason="no"
            )

    def test_restoring_clears_the_suspension(self, db_session, make_admin) -> None:
        admin = make_admin()
        target = make_admin(is_active=False)
        target.status = AccountStatus.SUSPENDED.value

        UserService(db_session).set_account_status(
            actor=admin, target=target, status=AccountStatus.ACTIVE, reason="appeal upheld"
        )
        assert target.is_active is True
        assert target.status == AccountStatus.ACTIVE.value

    def test_the_reason_is_audited(self, db_session, make_admin) -> None:
        from app.db.models.audit import AuditLog

        admin = make_admin()
        target = make_admin()
        UserService(db_session).set_account_status(
            actor=admin, target=target, status=AccountStatus.SUSPENDED, reason="plagiarism"
        )
        db_session.flush()

        row = next(
            r
            for r in db_session.execute(select(AuditLog)).scalars().all()
            if r.resource_id == target.id and r.action == AuditAction.ACCOUNT_DISABLED.value
        )
        assert row.metadata_["reason"] == "plagiarism"


class TestSelfOrAdminGuard:
    def test_a_user_may_read_their_own_account(self, db_session, make_user) -> None:
        user = make_user()
        assert (
            UserService(db_session).require_self_or_admin(actor=user, target_id=user.id).id
            == user.id
        )

    def test_a_user_may_not_read_another(self, db_session, make_user) -> None:
        victim = make_user()
        attacker = make_user()
        with pytest.raises(ForbiddenError):
            UserService(db_session).require_self_or_admin(actor=attacker, target_id=victim.id)

    def test_an_admin_may_read_any_account(self, db_session, make_admin) -> None:
        admin = make_admin()
        target = make_admin()
        assert (
            UserService(db_session).require_self_or_admin(actor=admin, target_id=target.id).id
            == target.id
        )


# =========================================================================== #
# Database guards                                                            #
# =========================================================================== #
@pytest.mark.slow
class TestDatabaseGuards:
    """Exercises the hand-written DDL from ``app/db/guards.py``."""

    def test_the_lowercase_email_constraints_exist(self, db_session) -> None:
        expected = {
            "users": "ck_users_email_lowercase",
            "verification_requests": "ck_verification_requests_verifier_email_lowercase",
            "worker_references": "ck_worker_references_email_lowercase",
        }
        for table, constraint in expected.items():
            result = db_session.execute(
                text("SELECT count(*) FROM pg_constraint WHERE conname = :c"), {"c": constraint}
            ).scalar_one()
            assert result == 1, f"{constraint} is missing from {table}"

    def test_the_availability_consistency_check_exists(self, db_session) -> None:
        result = db_session.execute(
            text(
                "SELECT count(*) FROM pg_constraint "
                "WHERE conname = 'ck_worker_profiles_available_from_required'"
            )
        ).scalar_one()
        assert result == 1

    def test_the_append_only_trigger_exists_and_is_row_level(self, db_session) -> None:
        definition = db_session.execute(
            text(
                "SELECT pg_get_triggerdef(oid) FROM pg_trigger "
                "WHERE tgname = 'audit_logs_append_only' AND NOT tgisinternal"
            )
        ).scalar_one()
        assert "BEFORE DELETE OR UPDATE" in definition
        assert "FOR EACH ROW" in definition

    def test_the_guard_survives_a_drop_and_reinstall(self, db_session) -> None:
        """The downgrade path must be able to remove and re-add it cleanly."""
        from app.db import guards

        guards.drop_append_only_audit_guard(db_session.connection())
        db_session.commit()

        guards.create_append_only_audit_guard(db_session.connection())
        db_session.commit()

        count = db_session.execute(
            text("SELECT count(*) FROM pg_trigger WHERE tgname = 'audit_logs_append_only'")
        ).scalar_one()
        assert count == 1

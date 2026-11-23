package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import cats.effect.kernel.Ref
import munit.CatsEffectSuite
import run.hallpass.kernel.*

final class HumanAuthenticatorSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()
  private val otherTenant = TenantId.random()
  private val user = DirectoryUserId.random()
  private val principal: Principal.Human = Principal.Human(UserId.random())
  private val identity = ExternalIdentity.from("https://idp.example.com", "subject-1").toOption.get
  private val now = Instant.parse("2026-09-27T12:00:00Z")

  private def membership(in: TenantId = tenant, role: MembershipRole = MembershipRole.Admin) =
    TenantMembership(user, in, principal, role)

  /** A directory whose state the test changes between calls, as an operator would. */
  private final class MutableDirectory(
      users: Ref[IO, Map[ExternalIdentity, DirectoryUserId]],
      memberships: Ref[IO, Either[DirectoryError, Vector[TenantMembership]]]
  ) extends HumanDirectory[IO]:
    def userFor(value: ExternalIdentity) = users.get.map(current => Right(current.get(value)))
    def activeMemberships(value: DirectoryUserId) = memberships.get.map(_.map(_.filter(_.user == value)))

  private def directory(initial: Vector[TenantMembership]) =
    for
      users <- Ref.of[IO, Map[ExternalIdentity, DirectoryUserId]](Map(identity -> user))
      memberships <- Ref.of[IO, Either[DirectoryError, Vector[TenantMembership]]](Right(initial))
    yield (users, memberships, new HumanAuthenticator[IO](MutableDirectory(users, memberships)))

  test("an active membership authenticates the human in exactly that tenant") {
    directory(Vector(membership(), membership(otherTenant, MembershipRole.Member))).flatMap: (_, _, humans) =>
      for
        resolved <- humans.userFor(identity)
        human <- humans.authenticate(user, tenant, now)
        other <- humans.authenticate(user, otherTenant, now)
      yield
        assertEquals(resolved, Right(user))
        val context = human.toOption.get
        assertEquals(context.tenant, tenant)
        assertEquals(context.principal, principal)
        assertEquals(context.role, MembershipRole.Admin)
        assertEquals(context.authenticatedAt, now)
        assertEquals(other.map(_.role), Right(MembershipRole.Member))
  }

  test("a tenant the user is not a member of never authenticates, even with memberships elsewhere") {
    directory(Vector(membership(otherTenant))).flatMap: (_, _, humans) =>
      humans.authenticate(user, tenant, now).map: result =>
        assertEquals(result.left.toOption, Some(HumanAuthenticationError.NoActiveMembership))
  }

  test("removing a membership fails the next request closed") {
    directory(Vector(membership())).flatMap: (_, memberships, humans) =>
      for
        before <- humans.authenticate(user, tenant, now)
        _ <- memberships.set(Right(Vector.empty))
        after <- humans.authenticate(user, tenant, now)
      yield
        assert(before.isRight)
        assertEquals(after.left.toOption, Some(HumanAuthenticationError.NoActiveMembership))
  }

  test("a disabled user resolves to no user and has no memberships") {
    // The directory omits disabled users from both lookups (see authai_user_for_external_identity and
    // authai_active_memberships); the authenticator must treat that absence as a refusal.
    directory(Vector(membership())).flatMap: (users, memberships, humans) =>
      for
        _ <- users.set(Map.empty)
        _ <- memberships.set(Right(Vector.empty))
        login <- humans.userFor(identity)
        request <- humans.authenticate(user, tenant, now)
      yield
        assertEquals(login, Left(HumanAuthenticationError.UnknownIdentity))
        assertEquals(request.left.toOption, Some(HumanAuthenticationError.NoActiveMembership))
  }

  test("an unavailable directory is reported as unavailable, never as a missing membership") {
    directory(Vector(membership())).flatMap: (_, memberships, humans) =>
      memberships.set(Left(DirectoryError.Unavailable)) *>
        humans.authenticate(user, tenant, now).map: result =>
          assertEquals(result.left.toOption, Some(HumanAuthenticationError.Unavailable))
  }

  test("external identities are validated before lookup") {
    assert(ExternalIdentity.from("", "subject").isLeft)
    assert(ExternalIdentity.from("https://idp.example.com", " padded").isLeft)
    assert(ExternalIdentity.from("https://idp.example.com", "s" * 256).isLeft)
  }

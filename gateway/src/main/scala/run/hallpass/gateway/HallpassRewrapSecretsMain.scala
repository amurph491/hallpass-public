package run.hallpass.gateway

import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import run.hallpass.adapters.postgres.{DatabaseConfig, DatabaseSafetyException, ProviderSecretRewrap}
import run.hallpass.adapters.secrets.VaultTransitKeyEncryption

/** One-shot operator job for key rotation. Run it after rotating the transit key in Vault
  * (`vault write -f transit/keys/<key>/rotate`). It re-encrypts every stored data key under the newest key version
  * inside Vault (rewrap), so no data key or provider secret is decrypted into this process.
  *
  * It connects as the schema owner (`HALLPASS_DB_USER`, like `HallpassMigrateMain`) and uses the same
  * `HALLPASS_SECRET_STORE=vault-transit` settings as the API. It exits non-zero if any secret could not be rewrapped.
  *
  * Rollback: rotation only adds a key version, and a rewrapped data key is the same data key. Until the operator raises
  * the transit key's `min_decryption_version`, both old and new wrapped keys decrypt, so rolling back the API or this
  * job needs no data change. Raise `min_decryption_version` only after a run reports zero failures. */
object HallpassRewrapSecretsMain extends IOApp:
  def run(args: List[String]): IO[ExitCode] =
    val configuration =
      for
        _ <- Either.cond(args.isEmpty, (), "usage: HallpassRewrapSecretsMain (configured through the environment)")
        database <- DatabaseConfig.fromEnvironment(sys.env)
        store <- OAuthRuntime.storeFromEnvironment(sys.env)
        vault <- store match
          case OAuthRuntime.StoreSelection.VaultTransit(config) => Right(config)
          case OAuthRuntime.StoreSelection.Local(_)             => Left("HALLPASS_SECRET_STORE=vault-transit is required")
      yield (database, vault)
    configuration match
      case Left(error) => IO.consoleForIO.errorln(error).as(ExitCode.Error)
      case Right((database, vault)) =>
        VaultTransitKeyEncryption
          .create(vault)
          .flatMap(ProviderSecretRewrap.run(database, _))
          .flatMap: report =>
            IO.println(
              s"Rewrap finished across ${report.tenants} tenants: ${report.rewrapped} rewrapped, ${report.alreadyCurrent} already current, ${report.failed} failed."
            ).as(if report.failed == 0 then ExitCode.Success else ExitCode.Error)
          .recoverWith:
            case refusal: DatabaseSafetyException => IO.consoleForIO.errorln(refusal.message).as(ExitCode.Error)

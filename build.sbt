ThisBuild / scalaVersion := "3.3.7"
ThisBuild / organization := "io.github.ondeoma"
ThisBuild / version      := "0.1.0-SNAPSHOT"
ThisBuild / licenses     := List("MIT" -> url("https://opensource.org/licenses/MIT"))
ThisBuild / homepage     := Some(url("https://github.com/Ondeoma/sruru"))
ThisBuild / scalacOptions ++= Seq("-deprecation", "-feature", "-Wunused:imports")

val http4sV = "1.0.0-M49"
val circeV  = "0.14.16"
val doobieV = "1.0.0-RC12"
val ceV     = "3.7.1"
val munitV  = "1.3.6"
val flywayV = "11.3.0"
val bcV     = "1.80"
val otel4sV = "1.2.0"
val otelV   = "1.68.0"
val otelInstV = "2.33.1-alpha"

lazy val commonTest = Seq(
  libraryDependencies ++= Seq(
    "org.scalameta" %% "munit"             % munitV  % Test,
    "org.typelevel" %% "munit-cats-effect" % "2.2.1" % Test
  ),
  Test / fork := true
)

// バックエンドと画面(Scala.js)で共有する API の型
lazy val shared = crossProject(JVMPlatform, JSPlatform)
  .crossType(CrossType.Full) // 日時(Timestamp)だけ JVM と JS で実装が違う
  .in(file("modules/shared"))
  .settings(
    libraryDependencies ++= Seq(
      "io.circe" %%% "circe-core"   % circeV,
      "io.circe" %%% "circe-parser" % circeV
    )
  )

// 画面: Scalactive の SPA（frontend/ の Vite から読み込む）
lazy val web = (project in file("modules/web"))
  .enablePlugins(ScalaJSPlugin, ScalactivePlugin)
  .dependsOn(shared.js)
  .settings(
    scalaJSLinkerConfig ~= (_.withModuleKind(ModuleKind.ESModule)),
    scalaJSUseMainModuleInitializer := true,
    libraryDependencies ++= Seq(
      "io.github.ondeoma" %%% "scalactive" % "0.6.2"
    )
  )

// ドメイン（純粋なロジック: パスワードポリシー・IP 制限・属性の式・SCIM のフィルター）
lazy val core = (project in file("modules/core"))
  .dependsOn(shared.jvm)
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "io.circe" %% "circe-parser" % circeV
    )
  )

// 暗号（パスワードのハッシュ・JWS/JWK・TOTP・X.509・秘密の値の暗号化）
lazy val security = (project in file("modules/security"))
  .dependsOn(core)
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcprov-jdk18on" % bcV,
      "org.bouncycastle" % "bcpkix-jdk18on" % bcV
    )
  )

lazy val db = (project in file("modules/db"))
  .dependsOn(core, observe)
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.tpolecat"  %% "doobie-core"           % doobieV,
      "org.tpolecat"  %% "doobie-hikari"         % doobieV,
      "org.tpolecat"  %% "doobie-postgres"       % doobieV,
      "org.tpolecat"  %% "doobie-postgres-circe" % doobieV,
      "org.typelevel" %% "cats-effect"           % ceV,
      "org.postgresql" % "postgresql"            % "42.7.14",
      "org.flywaydb"   % "flyway-core"           % flywayV,
      "org.flywaydb"   % "flyway-database-postgresql" % flywayV % Runtime
    )
  )

// SAML 2.0 の IdP（XML の署名・メタデータ・AuthnRequest の解析）
lazy val saml = (project in file("modules/saml"))
  .dependsOn(core, security)
  .settings(commonTest)

// 外部の IdP（Google Workspace・Microsoft Entra ID・汎用 OIDC）でのログインと、ディレクトリの同期
lazy val federation = (project in file("modules/federation"))
  .dependsOn(core, security)
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % http4sV,
      "org.http4s" %% "http4s-circe"  % http4sV
    )
  )

lazy val notifier = (project in file("modules/notify"))
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.eclipse.angus" % "angus-mail"  % "2.0.3",
      "org.typelevel"    %% "cats-effect" % ceV
    )
  )

// 観測（OpenTelemetry: otel4s-oteljava）. ログ・メトリクス・トレースを OTLP で skorimako に送る
lazy val observe = (project in file("modules/observe"))
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.typelevel"   %% "otel4s-oteljava"                 % otel4sV,
      "org.typelevel"   %% "otel4s-oteljava-context-storage" % otel4sV,
      "org.typelevel"   %% "otel4s-instrumentation-metrics"  % otel4sV,
      "io.opentelemetry" % "opentelemetry-exporter-otlp"     % otelV,
      "io.opentelemetry.instrumentation" % "opentelemetry-logback-appender-1.0" % otelInstV,
      "io.opentelemetry.instrumentation" % "opentelemetry-logback-mdc-1.0"      % otelInstV,
      "io.opentelemetry.instrumentation" % "opentelemetry-runtime-telemetry"    % otelInstV,
      "org.http4s"      %% "http4s-server"                   % http4sV,
      "org.http4s"      %% "http4s-client"                   % http4sV,
      "org.http4s"      %% "http4s-circe"                    % http4sV,
      "org.http4s"      %% "http4s-dsl"                      % http4sV,
      "ch.qos.logback"   % "logback-classic"                 % "1.5.18",
      "org.tpolecat"    %% "doobie-core"                     % doobieV
    )
  )

// プッシュ通知（PWA. Web Push の暗号化と VAPID は JDK の暗号の機能だけで実装）
lazy val push = (project in file("modules/push"))
  .dependsOn(db, observe)
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % http4sV,
      "io.circe"   %% "circe-core"    % circeV
    )
  )

lazy val api = (project in file("modules/api"))
  .dependsOn(core, db % "compile;test->test", security, saml, federation, notifier, shared.jvm, observe, push)
  .settings(commonTest)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-dsl"    % http4sV,
      "org.http4s" %% "http4s-circe"  % http4sV,
      "org.http4s" %% "http4s-server" % http4sV,
      "org.http4s" %% "http4s-ember-client" % http4sV % Test
    )
  )

lazy val app = (project in file("modules/app"))
  .dependsOn(api)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s"    %% "http4s-ember-server" % http4sV,
      "org.http4s"    %% "http4s-ember-client" % http4sV,
      "ch.qos.logback" % "logback-classic"     % "1.5.18",
      "org.typelevel" %% "log4cats-slf4j"      % "2.8.0"
    ),
    Compile / mainClass := Some("sruru.app.Main"),
    fork := true
  )

lazy val root = (project in file("."))
  .aggregate(shared.jvm, shared.js, web, core, security, db, saml, federation, notifier, observe, push, api, app)
  .settings(name := "sruru", publish / skip := true)

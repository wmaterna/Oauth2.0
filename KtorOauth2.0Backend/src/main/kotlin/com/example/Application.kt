package com.example

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.example.oauth.authGithub
import com.example.oauth.authenticationRoutes
import com.example.oauth.fbOauth
import com.example.oauth.oauthSlack
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.html.*
import io.ktor.server.routing.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.html.*
import io.ktor.serialization.gson.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import com.slack.api.Slack;



data class User(val id: String, val name: String)

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused")
fun Application.module() {

    val secret = System.getenv("KTOR_JWT_SECRET")
    val issuer =  System.getenv("KTOR_JWT_ISSUER")
    val audience =  System.getenv("KTOR_JWT_AUDIENCE")
    val myRealm =  System.getenv("KTOR_JWT_REALM")

    install(Authentication) {

        oauth("auth-oauth-google") {
            urlProvider = { "http://localhost:8080/hello" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "google",
                    authorizeUrl = "https://accounts.google.com/o/oauth2/auth",
                    accessTokenUrl = "https://accounts.google.com/o/oauth2/token",
                    requestMethod = HttpMethod.Post,
                    clientId = System.getenv("GOOGLE_CLIENT_ID"),
                    clientSecret = System.getenv("GOOGLE_CLIENT_SECRET"),
                    defaultScopes = listOf("https://www.googleapis.com/auth/userinfo.profile")
                )
            }
            client = HttpClient(CIO)
        }
        oauth("auth-oauth-github") {
            urlProvider = { "http://localhost:8080/oauth-github" }
            client = HttpClient(CIO)
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "github",
                    authorizeUrl = "https://github.com/login/oauth/authorize",
                    accessTokenUrl = "https://github.com/login/oauth/access_token",
                    requestMethod = HttpMethod.Post,
                    clientId = System.getenv("GITHUB_CLIENT_ID"),
                    clientSecret = System.getenv("GITHUB_CLIENT_SECRET")
                )
            }
        }

        oauth("auth-oauth-slack") {
            urlProvider = { System.getenv("NGROK_ADDRESS") + "/hello-slack"}
            client = HttpClient(CIO)
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "slack",
                    authorizeUrl = "https://slack.com/openid/connect/authorize?scope=openid%20profile%20email",
                    accessTokenUrl = "https://slack.com/api/openid.connect.token",
                    requestMethod = HttpMethod.Post,
                    clientId = System.getenv("SLACK_CLIENT_ID"),
                    clientSecret = System.getenv("SLACK_CLIENT_SECRET")
                )
            }
        }

        oauth("auth-oauth-facebook") {
            urlProvider = { System.getenv("NGROK_ADDRESS") + "/people/auth/facebook/callback" }
            client = HttpClient(CIO)
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "facebook",
                    authorizeUrl = "https://www.facebook.com/v8.0/dialog/oauth",
                    accessTokenUrl = "https://graph.facebook.com/v8.0/oauth/access_token",
                    requestMethod = HttpMethod.Get,
                    clientId = System.getenv("FB_CLIENT_ID"),
                    clientSecret = System.getenv("FB_CLIENT_SECRET"),
                    defaultScopes = listOf("public_profile", "email")
                )
            }
        }

        jwt("auth-jwt") {
            realm = myRealm
            verifier(
                JWT
                    .require(Algorithm.HMAC256(secret))
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .build())

            validate { credential ->
                if (credential.payload.getClaim("name").asString() != "") {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
            challenge { defaultScheme, realm ->
                call.respond(HttpStatusCode.Unauthorized, "Token is not valid or has expired")
            }
        }

    }
    install(CORS) {
        allowHost("*")
        allowHeader(HttpHeaders.ContentType)
    }

    install(ContentNegotiation) {
        gson()
        json()
    }
    install(Routing) {
        fbOauth()
        authenticationRoutes()
        authGithub()
        oauthSlack()
    }
}




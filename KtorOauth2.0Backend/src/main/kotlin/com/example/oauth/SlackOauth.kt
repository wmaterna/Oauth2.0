package com.example.oauth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import java.util.*

fun Route.oauthSlack(httpClient: HttpClient = httC) {

    val secret = System.getenv("KTOR_JWT_SECRET")
    val issuer =  System.getenv("KTOR_JWT_ISSUER")
    val audience =  System.getenv("KTOR_JWT_AUDIENCE")

    authenticate("auth-oauth-facebook") {
        get("/login-slack") {
        }
        get("/hello-slack") {
            val principal: OAuthAccessTokenResponse.OAuth2? = call.principal()
            if(principal?.accessToken.toString() != null){
                val userInfo: SlackUser = httpClient.get("https://slack.com/api/openid.connect.userInfo") {
                    headers {
                        append(HttpHeaders.Authorization, "Bearer ${principal?.accessToken.toString()}")
                    }
                }.body()

                val token = JWT.create()
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .withClaim("name", userInfo.name)
                    .withExpiresAt(Date(System.currentTimeMillis() + 60000))
                    .sign(Algorithm.HMAC256(secret))
                call.response.cookies.append(
                    Cookie(
                        "jwt-token",
                        token,
                    )
                )
                call.respondText("Hello ${userInfo.name}");
                call.response.headers.append("Authorization", "Bearer $token")
                call.respondRedirect("http://localhost:3000/user/info")
            } else {
                call.respondRedirect("/")
            }
        }
    }
}

@Serializable
data class SlackUser(
    val name: String,
)


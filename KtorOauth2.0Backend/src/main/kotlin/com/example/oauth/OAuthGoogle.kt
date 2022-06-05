package com.example.oauth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.serialization.gson.*
import kotlinx.serialization.Serializable
import java.util.*

val httC = HttpClient(CIO) {
    install(ContentNegotiation) {
        gson()
    }
}


fun Route.authenticationRoutes(httpClient: HttpClient = httC) {

    val secret = System.getenv("KTOR_JWT_SECRET")
    val issuer =  System.getenv("KTOR_JWT_ISSUER")
    val audience =  System.getenv("KTOR_JWT_AUDIENCE")


    authenticate("auth-oauth-google") {
        get("/login-google") {
        }
        get("/hello") {
            val principal: OAuthAccessTokenResponse.OAuth2? = call.principal()
            if(principal?.accessToken.toString() != null){
                val userInfo: UserInfo = httpClient.get("https://www.googleapis.com/oauth2/v2/userinfo") {
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
                call.response.headers.append("Authorization", "Bearer $token")
                call.respondRedirect("http://localhost:3000/user/info")

            } else {
                call.respondRedirect("/")
            }
        }

    }
}

@Serializable
data class UserInfo(
    val id: String,
    val name: String,
)
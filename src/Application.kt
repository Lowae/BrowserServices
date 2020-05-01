package com.hao.browser

import com.auth0.jwt.*
import com.auth0.jwt.algorithms.Algorithm
import com.fasterxml.jackson.databind.SerializationFeature
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.*
import io.ktor.auth.jwt.*
import org.jetbrains.exposed.dao.id.EntityID
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.html.respondHtml
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpStatusCode
import io.ktor.http.auth.parseAuthorizationHeader
import io.ktor.jackson.jackson
import io.ktor.request.receive
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.util.date.GMTDate
import kotlinx.html.*
import org.apache.http.auth.InvalidCredentialsException
import org.jetbrains.exposed.dao.*
import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import java.util.Date
import kotlin.time.ExperimentalTime
import kotlin.time.seconds

const val jwtAuth = "jwt-auth"
const val formAuth = "form-auth"
const val COOKIE_JWT_KEY_NAME = "JWT"
const val TOKEN_AUTH_SCHEMES = "token"
const val JWT_SECRET = "asdkjkajsdkjqwne"
const val INPUT_USERNAME = "username"
const val INPUT_PASSWORD = "password"
const val ISSUER = "ktor-demo"

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    Database.connect(
        url = "jdbc:mysql://0.0.0.0:3306/test?useUnicode=true&characterEncoding=UTF-8&useSSL=false&serverTimezone=Asia/Shanghai",
        user = "root",
        password = "lh19990428",
        driver = "com.mysql.jdbc.Driver"
    )
    transaction { SchemaUtils.createMissingTablesAndColumns(Users) }

    install(StatusPages) {
        exception<InvalidCredentialsException> { exception ->
            call.respond(HttpStatusCode.Unauthorized, mapOf("OK" to false, "error" to (exception.message ?: "")))
        }
    }
    install(Authentication) {
        jwt(name = jwtAuth) {
            authHeader { call ->
                call.request.cookies[COOKIE_JWT_KEY_NAME]?.let { parseAuthorizationHeader(it) }
            }
            authSchemes(TOKEN_AUTH_SCHEMES)
            verifier(JWTUtil.provideVerifier(ISSUER))

            validate { credential ->
                with(credential.payload) {
                    if (subject == null) return@validate null
                }
                return@validate JWTPrincipal(credential.payload)
            }
            challenge { _, _ ->
                call.respond("token核验不通过!!")
            }
        }
        form(name = formAuth) {
            userParamName = INPUT_USERNAME
            passwordParamName = INPUT_PASSWORD

            validate { credentials ->
                return@validate UserService.getUserByName(credentials.name)?.let {
                    if (it.password == credentials.password) {
                        return@let UserIdPrincipal(it.username)
                    }
                    null
                }
            }
            challenge {
                call.respondText { "账号或者密码错误" }
            }
        }
    }

    install(ContentNegotiation) {
        jackson {
            enable(SerializationFeature.INDENT_OUTPUT)
        }
    }

    routing {
        authenticate(formAuth) {
            post("/login") {
                val name = call.authentication.principal<UserIdPrincipal>()!!.name
                val token = JWTUtil.createToken(ISSUER, name)
                call.response.cookies.append(
                    Cookie(
                        name = COOKIE_JWT_KEY_NAME, value = "$TOKEN_AUTH_SCHEMES $token",
                        expires = GMTDate(JWTUtil.expiredAt + System.currentTimeMillis()),
                        httpOnly = true
                    )
                )
                call.respond(mapOf("OK" to true))
            }
        }

        post("/register") {
            val post = call.receive<LoginRegister>()
            if (UserService.register(post.username, post.password)._readValues != null) {
                call.respond(mapOf("OK" to true))
            } else throw InvalidCredentialsException("server error")
        }

        get("/") {
            call.respondText("HELLO WORLD!", ContentType.Text.Plain)
        }
    }
}

object JWTUtil {
    private val algorithm = Algorithm.HMAC512(JWT_SECRET)!!
    const val expiredAt = 7 * 24 * 60 * 1000

    fun provideVerifier(jwtIssuer: String): JWTVerifier = JWT.require(algorithm).withIssuer(jwtIssuer).build()

    fun createToken(issuer: String, name: String): String =
        JWT.create().withIssuer(issuer)
            .withSubject(name)
            .withExpiresAt(Date(System.currentTimeMillis() + expiredAt))
            .sign(algorithm)
}

object Users : IntIdTable(name = "user") {
    val username = varchar("username", 50).uniqueIndex()
    val password = varchar("password", 100)
}

class User(id: EntityID<Int>) : IntEntity(id) {
    companion object : IntEntityClass<User>(Users)

    var username by Users.username
    var password by Users.password
}

class LoginRegister(val username: String, val password: String)

object UserService {
    fun getUserByName(username: String): User? {
        return transaction {
            User.find { Users.username eq username }.firstOrNull()
        }
    }

    fun register(username: String, password: String): User {
        return transaction {
            return@transaction User.new {
                this.username = username
                this.password = password
            }
        }

    }
}
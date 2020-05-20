package com.hao.browser

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.fasterxml.jackson.databind.SerializationFeature
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.*
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.jwt.jwt
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.auth.parseAuthorizationHeader
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.http.content.streamProvider
import io.ktor.jackson.jackson
import io.ktor.request.receive
import io.ktor.request.receiveMultipart
import io.ktor.response.header
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.route
import io.ktor.routing.routing
import io.ktor.util.date.GMTDate
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import org.apache.http.auth.InvalidCredentialsException
import org.jetbrains.exposed.dao.IntEntity
import org.jetbrains.exposed.dao.IntEntityClass
import org.jetbrains.exposed.dao.id.EntityID
import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.*

const val jwtAuth = "jwt-auth"
const val formAuth = "form-auth"
const val COOKIE_JWT_KEY_NAME = "JWT"
const val TOKEN_AUTH_SCHEMES = "token"
const val JWT_SECRET = "asdkjkajsdkjqwne"
const val INPUT_USERNAME = "username"
const val INPUT_PASSWORD = "password"
const val ISSUER = "ktor-demo"
const val SAVE_FILE_PATH = "/home/Files"

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    Database.connect(
        url = "jdbc:mysql://127.0.0.1:3306/test?useUnicode=true&characterEncoding=UTF-8&autoReconnect=true&failOverReadOnly=false&maxReconnects=10",
        user = "root",
        password = "Lh19990428.",
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
                call.respond(mapOf("OK" to true, "token" to token))
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

        post("/file") {
            println("---------------------- file ---------------------")
            val multiPart = call.receiveMultipart()
            multiPart.forEachPart { part ->
                when (part.contentType) {
                    ContentType.MultiPart.FormData -> {
                        println(part.contentType)
			val data = part as PartData.FileItem
                        val username = part.headers["Authorization"] ?: return@forEachPart
                        val ext = File(data.originalFileName.toString()).extension
                        println("name: $username --- ext: $ext")
			val file =
                            File(SAVE_FILE_PATH, "${username}-${System.currentTimeMillis()}.$ext")
                        data.streamProvider().use { input ->
                            file.outputStream().buffered().use { output ->
                                input.copyToSuspend(output)
                            }
                        }
                        UserService.update(username, file.absolutePath)
                        println("success -------- ${file.absolutePath}")
                    }
                    else -> {
                    }
                }
                part.dispose()
            }
        }

        get("/file") {
            val username = call.request.queryParameters["Authorization"]
            val fileName = UserService.getUserByName(username.toString())?.path
            call.response.header(HttpHeaders.ContentDisposition, "attachment; filename=\"$fileName\"")
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
    val path = varchar("path", 50).default("")
}

class User(id: EntityID<Int>) : IntEntity(id) {
    companion object : IntEntityClass<User>(Users)

    var username by Users.username
    var password by Users.password
    var path by Users.path
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

    fun update(username: String, path: String): Boolean {
        return transaction {
            val result = User.find { Users.username eq username }
            if (result.empty()) {
                return@transaction false
            } else {
                result.first().path = path
                return@transaction true
            }
        }
    }
}

suspend fun InputStream.copyToSuspend(
    out: OutputStream,
    bufferSize: Int = DEFAULT_BUFFER_SIZE,
    yieldSize: Int = 4 * 1024 * 1024,
    dispatcher: CoroutineDispatcher = Dispatchers.IO
): Long {
    return withContext(dispatcher) {
        val buffer = ByteArray(bufferSize)
        var bytesCopied = 0L
        var bytesAfterYield = 0L
        while (true) {
            val bytes = read(buffer).takeIf { it >= 0 } ?: break
            out.write(buffer, 0, bytes)
            if (bytesAfterYield >= yieldSize) {
                yield()
                bytesAfterYield %= yieldSize
            }
            bytesCopied += bytes
            bytesAfterYield += bytes
        }
        return@withContext bytesCopied
    }
}

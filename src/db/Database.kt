package db

import org.jetbrains.exposed.dao.id.EntityID
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction

class UserDbHelper(private val db: Database) {

    fun insert(email: String, password: String): EntityID<Int> {
        return transaction(db) {
            addLogger(StdOutSqlLogger)

            return@transaction Users.insertAndGetId {
                it[this.email] = email
                it[this.password] = password
            }
        }

    }

    fun query(email: String, password: String): Boolean {

        return transaction(db)  {
            addLogger(StdOutSqlLogger)

            return@transaction Users.select {
                Op.build {
                    Users.email eq email and (Users.password eq password)
                }
            }.empty()

        }
    }

    fun queryAll(): Query {
        return transaction(db) {
            return@transaction Users.selectAll()
        }
    }

    fun update(email: String, password: String, newPassword: String): Int {
        return transaction(db)  {
            return@transaction Users.update({ Users.email eq email and (Users.password eq password) }) {
                it[this.password] = newPassword
            }
        }
    }
}

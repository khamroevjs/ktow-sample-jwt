package com.example.routing.response

import com.example.util.UUIdSerializer
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class UserResponse(
    @Serializable(with = UUIdSerializer::class)
    val id: UUID,
    val username: String,
)

from datetime import datetime

from sqlalchemy import (
    BigInteger, DateTime, Double, ForeignKey, Integer, String, Text, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(10), default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime(3), server_default=func.now(3))


class Vlan(Base):
    __tablename__ = "vlans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    cidr: Mapped[str | None] = mapped_column(String(50))
    color: Mapped[str] = mapped_column(String(7), default="#a78bfa")
    created_at: Mapped[datetime] = mapped_column(DateTime(3), server_default=func.now(3))


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100))
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    type: Mapped[str] = mapped_column(String(20), default="server")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    x: Mapped[float | None] = mapped_column(Double)
    y: Mapped[float | None] = mapped_column(Double)
    vlan_id: Mapped[int] = mapped_column(ForeignKey("vlans.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(3), server_default=func.now(3))

    vlan: Mapped["Vlan"] = relationship()


class Link(Base):
    __tablename__ = "links"

    source_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(3), server_default=func.now(3))


class Telemetry(Base):
    __tablename__ = "telemetry"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    cpu_usage: Mapped[float] = mapped_column(Double)
    ram_usage: Mapped[float] = mapped_column(Double)
    traffic_in_mbps: Mapped[float] = mapped_column(Double, default=0)
    packet_loss: Mapped[float] = mapped_column(Double, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(3), server_default=func.now(3))


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lv: Mapped[str] = mapped_column(String(10), default="info")
    title: Mapped[str] = mapped_column(String(200))
    msg: Mapped[str] = mapped_column(Text)
    cause: Mapped[str] = mapped_column(String(500), default="")
    action: Mapped[str] = mapped_column(String(500), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(3), server_default=func.now(3))


class AlertDevice(Base):
    __tablename__ = "alert_devices"

    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), primary_key=True)
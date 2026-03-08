#pragma once

namespace blook {
enum class Protect {
  None = 0,
  Read = 0x0001,
  Write = 0x0010,
  Execute = 0x0100,
  ReadWrite = Read | Write,
  ReadWriteExecute = Read | Write | Execute,
  ReadExecute = Read | Execute,
  rw = ReadWrite,
  rwx = ReadWriteExecute,
  rx = ReadExecute
};

}
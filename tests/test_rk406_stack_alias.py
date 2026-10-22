"""Regression coverage for the stack-alias error found in the 4.06 audit."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_rk406_g5_vcall_resolution import verify_stack_alias


class StackAliasRegression(unittest.TestCase):
    SETUP = [
        "mov edx,dword ptr [esp+0x50]",
        "add esp,0x14",
        "push 0x8135",
        "lea ecx,[esp+0x5c]",
        "push ecx",
        "push eax",
        "mov eax,dword ptr [edx+0x68]",
        "push esi",
        "lea ecx,[esp+0x4c]",
        "call eax",
    ]

    def test_pending_format_arguments_make_receiver_addresses_equal(self):
        verify_stack_alias(self.SETUP, "eax")

    def test_ignoring_caller_cleanup_rejects_the_alias(self):
        with self.assertRaises(RuntimeError):
            verify_stack_alias([asm for asm in self.SETUP if asm != "add esp,0x14"], "eax")

    def test_separate_graphics_slot_does_not_alias_adapter(self):
        changed = self.SETUP.copy()
        # Baseline+0x50 is [ESP+0x64] while five cdecl args are pending.
        changed[0] = "mov edx,dword ptr [esp+0x64]"
        with self.assertRaises(RuntimeError):
            verify_stack_alias(changed, "eax")

    def test_overwritten_target_origin_is_rejected(self):
        for instruction in ("xor edx,edx", "shl edx,0x1", "mov dl,0x0"):
            with self.subTest(instruction=instruction):
                changed = self.SETUP.copy()
                changed.insert(6, instruction)
                with self.assertRaises(RuntimeError):
                    verify_stack_alias(changed, "eax")

    def test_unsupported_stack_pointer_writes_fail_closed(self):
        for instruction in ("lea esp,[esp+0x4]", "mov esp,ebp", "pop esp", "and esp,0xfffffff0", "add esp,edx"):
            with self.subTest(instruction=instruction):
                changed = self.SETUP.copy()
                changed.insert(2, instruction)
                with self.assertRaises(RuntimeError):
                    verify_stack_alias(changed, "eax")

    def test_full_and_partial_target_clobbers_are_rejected(self):
        for instruction in ("shl eax,0x1", "mov al,0x0", "mov ax,0x0"):
            with self.subTest(instruction=instruction):
                changed = self.SETUP.copy()
                changed.insert(-1, instruction)
                with self.assertRaises(RuntimeError):
                    verify_stack_alias(changed, "eax")

    def test_implicit_register_writes_fail_closed(self):
        changed = self.SETUP.copy()
        changed.insert(-1, "mul ebx")
        with self.assertRaises(RuntimeError):
            verify_stack_alias(changed, "eax")

    def test_branch_discards_incoming_origin(self):
        changed = self.SETUP.copy()
        changed.insert(2, "jne 0x123456")
        with self.assertRaises(RuntimeError):
            verify_stack_alias(changed, "eax")

    def test_non_dword_stack_operations_are_rejected(self):
        for instruction in ("push ax", "pop ax", "push word ptr [esp+0x4]"):
            with self.subTest(instruction=instruction):
                changed = self.SETUP.copy()
                changed.insert(2, instruction)
                with self.assertRaises(RuntimeError):
                    verify_stack_alias(changed, "eax")


if __name__ == "__main__":
    unittest.main()

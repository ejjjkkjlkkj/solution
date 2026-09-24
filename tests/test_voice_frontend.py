import unittest

from omni.voice_frontend import Language, TokenKind, expand_number, normalize_for_speech


class VoiceFrontendTests(unittest.TestCase):
    def test_french_number_rules_cover_uefi_values(self):
        self.assertEqual(expand_number("71", Language.FR), "soixante et onze")
        self.assertEqual(expand_number("80", Language.FR), "quatre-vingts")
        self.assertEqual(
            expand_number("8192", Language.FR),
            "huit mille cent quatre-vingt-douze",
        )

    def test_english_number_rules_cover_uefi_values(self):
        self.assertEqual(
            expand_number("8192", Language.EN),
            "eight thousand one hundred ninety-two",
        )

    def test_firmware_acronyms_are_renderer_neutral(self):
        tokens = normalize_for_speech("USB AHCI EFI NVRAM", Language.FR)
        self.assertEqual([t.kind for t in tokens], [TokenKind.ACRONYM] * 4)
        self.assertEqual(
            [t.text for t in tokens],
            ["U S B", "A H C I", "E F I", "N V R A M"],
        )

    def test_clause_semantics_are_preserved(self):
        tokens = normalize_for_speech(
            "Secure Boot désactivé. Continuer ?",
            Language.FR,
        )
        self.assertEqual(tokens[-1].kind, TokenKind.CLAUSE)
        self.assertEqual(tokens[-1].text, "question")
        self.assertIn(
            "statement",
            [t.text for t in tokens if t.kind is TokenKind.CLAUSE],
        )

    def test_invalid_number_is_rejected(self):
        with self.assertRaises(ValueError):
            expand_number("12A", Language.FR)


if __name__ == "__main__":
    unittest.main()

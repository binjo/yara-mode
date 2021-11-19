;;; yara-mode.el --- Major mode for editing yara rule file

;; Copyright 2012 Binjo
;;
;; Author: binjo.cn@gmail.com
;; Version: $Id: yara-mode.el,v 0.0 2012/10/16 14:11:51 binjo Exp $
;; Keywords: yara
;; X-URL: not distributed yet
;; Package-Requires: ((emacs "24"))

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, write to the Free Software
;; Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

;;; Commentary:

;;

;;; History:

;; 2012/10/16, init
;; 2016/08/19, 1st pull request from @syohex

;; Put this file into your load-path and the following into your ~/.emacs:
;;   (require 'yara-mode)

;;; Code:

(require 'smie)
(require 'cc-langs)


(defvar yara-mode-hook nil)
(defvar yara-mode-map
  (make-keymap)
  "Keymap for YARA major mode.")

(defgroup yara-mode nil
  "Support for Yara code.")

(defcustom yara-indent-offset 4
  "Indent Yara code by this number of spaces."
  :type 'integer
  :group 'yara-mode
  :safe #'integerp)

(defcustom yara-indent-section 4
  "Indent the sections of rule in Yara code by this number of spaces."
  :type 'integer
  :group 'yara-mode
  :safe #'integerp)

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.ya?r" . yara-mode))

(defun yara-comment-dwim (arg)
  "Comment or uncomment current line or region in a smart way.
For ARG detail, see `comment-dwim'."
  (interactive "*P")
  (require 'newcomment)
  (let ((comment-start "//")
        (comment-start-skip "//")
        (comment-end ""))
    (comment-dwim arg)))

(defvar yara-smie-grammar nil
  "Yara BNF grammer only for indentation with `smie'.")

(setq yara-smie-grammar
      (smie-prec2->grammar
       (smie-bnf->prec2
        `((stmts (stmts "import" modulepath)
                 (stmts "include" filepath)
                 (stmts "rule" rulename "{" sections "}")
                 (stmts "rule" rulename ":" tags "{" sections "}"))
          (sections (sections "strings" ":" stringdefs)
                    (sections "condition" ":" condexpr)
                    (sections "meta" ":" metalist))
          (modulepath)
          (filepath)
          (rulename)
          (tags)
          (stringdefs)
          (condexpr)
          (metalist)))))

(defun yara-smie-rules (kind token)
  "Perform indentation of KIND on TOKEN using the `smie' engine."
  (let ((offset (pcase (cons kind token)
                  ('(:elem . arg) 0)
                  ('(:elem . basic) yara-indent-offset)
                  ('(:before . "{") (smie-rule-parent))
                  ('(:after . "}") 0)
                  ;; indentation of sections inner rule block
                  ('(:list-intro . ":") (not (smie-rule-prev-p "condition")))
                  (`(:before . ,(or "condition" "strings" "meta"))
                   (smie-rule-parent yara-indent-section))
                  ('(:after . ":")
                   (when (smie-rule-prev-p "condition" "strings" "meta")
                     yara-indent-offset)))))
    offset
    ))

(defvar yara-font-lock-keywords
  `(("^\\_<rule[\s\t]+\\([^\\$\s\t].*\\)\\_>"
     . (1 font-lock-function-name-face))
    ("^[\s\t]+\\([^\\$\s\t].*?\\)[\s\t]*=[\s\t]*"
     . (1 font-lock-constant-face))
    ("\\_<\\(\\$[^\s\t].*?\\)\\_>"
     . (1 font-lock-variable-name-face))
    ("\\([{/].*[}/]\\)"
     . (1 font-lock-string-face))
    ("\\<\\(0x[[:xdigit:]]*\\)\\>"
     . (1 font-lock-constant-face))
    (,(regexp-opt
       '("condition" "meta" "strings")
       'symbols)
     . font-lock-warning-face)
    (,(regexp-opt
       '("all" "and" "any" "ascii" "at" "base64" "base64wide" "contains" "icontains"
         "entrypoint" "false" "filesize" "fullword" "for" "global" "in"
         "import" "include"
         "matches" "nocase" "not" "or" "of"
         "private" "rule" "them" "true"
         "wide" "xor"
         "startswith" "istartswith" "endswith" "iendswith")
       'symbols)
     . font-lock-keyword-face)
    (,(regexp-opt
       '("int8" "int16" "int32" "int8be" "int16be" "int32be"
         "uint8" "uint16" "uint32" "uint8be" "uint16be" "uint32be")
       'symbols)
     . font-lock-function-name-face))
  "Keywords to highlight in yara-mode.")

(defvar yara-mode-syntax-table
  (funcall (c-lang-const c-make-mode-syntax-table c))
  "Syntax table for yara-mode.")

;;;###autoload
(define-derived-mode yara-mode prog-mode "Yara"
  "Major Mode for editing yara rule files."
  (define-key yara-mode-map [remap comment-dwim] 'yara-comment-dwim)
  (setq comment-start "//"
        comment-start-skip "//"
        comment-end "")
  (smie-setup yara-smie-grammar #'yara-smie-rules)
  (setq font-lock-defaults '(yara-font-lock-keywords nil t))
  (setq tab-width 4))

(provide 'yara-mode)

;;; yara-mode.el ends here

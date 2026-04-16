glass.sys - A system driver to assist in reading memory from a usermode process. You can find its implementation under the !kdump commands source code. It
safely reads memory inside of a remote process by avoiding a user supplied size parameter and reading page by page. This driver takes in a address and process
ID and spits out a page for you.

LATEX:=pdflatex
LATEXFLAGS:=-shell-escape -interaction=nonstopmode -file-line-error
DOCUMENT:=Group2-PetrolDesignDoc

.PHONY: all clean

all: $(DOCUMENT).pdf

$(DOCUMENT).pdf: main.tex
	$(LATEX) $(LATEXFLAGS) -ini -jobname="$(basename $@)" "&$(LATEX) $<\dump"

clean:
	$(RM) -v $(addprefix $(DOCUMENT).,aux log pdf)

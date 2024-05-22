package com.example.foro.controller;

import com.example.foro.model.Topico;
import com.example.foro.service.TopicoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/topicos")
public class TopicoController {

    @Autowired
    private TopicoService topicoService;

    @GetMapping
    public List<Topico> getAll() {
        return topicoService.findAll();
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping
    public Topico create(@RequestBody Topico topico) {
        return topicoService.save(topico);
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        topicoService.deleteById(id);
        return ResponseEntity.ok().build();
    }
}



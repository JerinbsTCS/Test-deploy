package com.example.pathtraversal;

// import java.nio.file.Path;
// import java.nio.file.Paths;

import java.io.File;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FileController {
    private final String BASE_PATH = "src/main/resources/static/";

    @GetMapping("/view")
    public ResponseEntity<Resource> readFile(@RequestParam String filename) {
        /* VULNERABLE CODE */
        File file = new File(BASE_PATH + filename);
        System.out.println("Requested file path: " + file.getAbsolutePath());
        if (!file.getAbsolutePath().startsWith(new File(BASE_PATH).getAbsolutePath())) {
            throw new SecurityException("Access Denied!");
        }
        if (!file.exists()) {
            return ResponseEntity.status(404).body(null);
        }

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(new FileSystemResource(file));

        /* SECURE CODE */
        // Path path = Paths.get(BASE_PATH).resolve(filename).normalize().toAbsolutePath();
        // System.out.println("Resolved path: " + path);
        // if (!path.startsWith(Paths.get(BASE_PATH).toAbsolutePath())) {
        //     throw new SecurityException("Access Denied!");
        // }
        // if (!path.toFile().exists()) {
        //     return ResponseEntity.status(404).body(null);
        // }

        // return ResponseEntity.ok()
        //         .contentType(MediaType.TEXT_PLAIN)
        //         .body(new FileSystemResource(path.toFile()));
    }

    @GetMapping("/test")
    public String test() {
        return "This is a test endpoint. Try accessing /view?filename=example.txt";
    }
} 
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecureFileExchange2FA.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class FileController : ControllerBase
{
    private readonly string _uploadDir = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("Fichier invalide.");

        Directory.CreateDirectory(_uploadDir);
        var path = Path.Combine(_uploadDir, file.FileName);

        using var stream = new FileStream(path, FileMode.Create);
        await file.CopyToAsync(stream);

        return Ok("Fichier uploadé avec succès.");
    }

    [HttpGet("download/{fileName}")]
    public IActionResult Download(string fileName)
    {
        var path = Path.Combine(_uploadDir, fileName);
        if (!System.IO.File.Exists(path))
            return NotFound("Fichier non trouvé.");

        var fileBytes = System.IO.File.ReadAllBytes(path);
        return File(fileBytes, "application/octet-stream", fileName);
    }

    [HttpGet("list")]
    public IActionResult List()
    {
        Directory.CreateDirectory(_uploadDir);
        var files = Directory.GetFiles(_uploadDir).Select(Path.GetFileName);
        return Ok(files);
    }
}
